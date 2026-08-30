// viz.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Explore + viz/charts: drilldown, fenetre glissante, requete interactive, rendu table/graphes (partages avec dashboards).
import { $, CSSV, LANG, LOC, SEV, api, apiSend, bornerLePopoverSousSonAncre, colComparator, confirmModal, esc, flashStopped, fmtTs, ic, makePager, muted, sev, socIsAdmin, toast, tzOpts } from './core.js';
import { S } from './state.js';
// P11.4-h : LE clic qui respecte une sélection (mécanisme partagé, `copie_et_selection.js`).
import { clicQuiRespecteLaSelection } from './copie_et_selection.js';
import { currentViewName, loadActions, loadDashboard, refresh, updateQRangeBtn, updateRangeBtn } from './app.js';
// `P11.18-a` : le réglage des axes se mémorise dans le magasin de préférences adossé au démon
// (self-scoped, viewer+), qui miroite lui-même dans `localStorage` — voir le bloc du réglage.
import { prefGet, prefSet } from './prefs.js';
import { recordRecentQuery } from './savedqueries.js';   // historique récent client-only (localStorage) : enregistré à chaque exécution

// Le zoom temporel (drag-select sur un graphe + clic-sur-bucket = drillTime) n'a de sens que sur les
// DASHBOARDS : sur Explore il est redondant avec le picker local (#qrange). On le borne dynamiquement.
function timeZoomEnabled() { return currentViewName() === 'dashboards'; }

// --- Plume panel : fil d'Ariane de drilldown. Quand un clic-drill atterrit dans le Plume panel (la
// surface Explore), on affiche « Détail : <source/filtre> (drillé) » dans l'en-tête -> l'opérateur sait
// POURQUOI il est là et peut l'effacer. Purement indicatif (n'altère NI la requête NI la fenêtre).
function setDrillCrumb(label) {
  const el = $('#qcrumb'); if (!el) return;
  const s = String(label == null ? '' : label).trim();
  if (!s) { clearDrillCrumb(); return; }
  el.hidden = false;
  el.innerHTML = `<span>drill :</span> <b>${esc(s)}</b>` +
    `<button type="button" id="qcrumb-x" title="Sortir du drill">${ic('x')}</button>`;
  const x = el.querySelector('#qcrumb-x'); if (x) x.onclick = resetDrill;
}

function clearDrillCrumb() { const el = $('#qcrumb'); if (el) { el.hidden = true; el.replaceChildren(); } }

// Sortir VRAIMENT du drill (le « x » du fil d'Ariane) : on annule la fenêtre zoomée, on vide la requête
// et les résultats, puis on retire le chip. (clearDrillCrumb ne fait que MASQUER le chip — utilisé en
// cours de flux par la recherche manuelle ; à ne pas confondre.)
function resetDrill() {
  if (S.zoomRange) { S.zoomRange = null; if (typeof updateZoomBadge === 'function') updateZoomBadge(); }
  if ($('#sql')) $('#sql').value = '';
  if ($('#qresult')) $('#qresult').replaceChildren();
  if ($('#qstats')) $('#qstats').textContent = '';
  clearDrillCrumb();
}

// --- drilldown : depuis une viz, retrouver les événements correspondants (avec tous les détails) ---
const DIMENSIONLESS = new Set(['ts', 'bucket']); // 1re colonne temporelle -> pas un axe de filtrage

function drilldown(field, value) {
  if (value == null || value === '' || !field || DIMENSIONLESS.has(field)) return;
  const lit = /^-?\d+(\.\d+)?$/.test(String(value)) ? String(value) : `"${String(value).replace(/"/g, '')}"`;
  const sqlBox = $('#sql');
  if (sqlBox) sqlBox.value = `search ${field}=${lit}`;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  setDrillCrumb(field + '=' + value);
  runQuery();
}

// clic sur un point/bucket temporel -> zoom sur la fenêtre + vue événements (les logs précis).
// DASHBOARDS UNIQUEMENT (sur Explore le picker local fait foi) — cf. les gardes timeZoomEnabled() aux clics.
function drillTime(t, span) {
  S.zoomRange = { from: Math.floor(t), to: Math.ceil(t + (span || 60)) };
  updateZoomBadge();
  if ($('#sql')) $('#sql').value = 'search';
  location.hash = 'explore';
  setDrillCrumb('période ' + fmtTs(S.zoomRange.from));
  // clic-drill : scope le Plume panel UNIQUEMENT (sa requête + sa fenêtre via zoomRange).
  // PAS de refresh()/loadDashboard() global -> on ne re-scope plus toute la page Dashboards.
  runQuery();
}

// B : drill CONFIGURABLE par panneau. Le panneau definit un GXQL avec des marqueurs
// $value (valeur cliquee), $from / $to (bornes du bucket temporel). Substitution sure :
// $value -> litteral entre guillemets, debarrasse de | [ ] " et retours ligne (anti-injection GXQL).
function sanitizeVal(v) { return '"' + String(v).replace(/[|\[\]"\n\r]/g, ' ').trim() + '"'; }

function customDrill(tpl, ctx) {
  if (!tpl) return;
  let q = tpl;
  if (ctx.value !== undefined && ctx.value !== null) q = q.split('$value').join(sanitizeVal(ctx.value));
  const timed = ctx.from !== undefined;
  if (timed) {
    const f = Math.floor(ctx.from), t = Math.ceil(ctx.to !== undefined ? ctx.to : ctx.from + 60);
    q = q.split('$from').join(String(f)).split('$to').join(String(t));
    S.zoomRange = { from: f, to: t }; updateZoomBadge(); // scope le Plume panel au bucket clique
  }
  if ($('#sql')) $('#sql').value = q;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  setDrillCrumb(ctx.value !== undefined && ctx.value !== null ? String(ctx.value) : (timed ? 'période ' + fmtTs(S.zoomRange.from) : 'drill'));
  // clic-drill : scope le Plume panel UNIQUEMENT. PAS de refresh()/loadDashboard() global pour la branche
  // temporelle -> on ne re-scope plus toute la page Dashboards (le drag-zoom dashboard reste, lui, intact).
  runQuery();
}

// C : clic sur un panneau "stat" (un seul chiffre) -> voir ce qu'il y a derriere.
// drill configure prioritaire ; sinon `search X | stats count` -> `search X` (les evenements) ;
// une requete metric/SQL (avec |) est ouverte telle quelle (GXQL detecte par le |).
function statDrill(query, drill) {
  if (drill) return customDrill(drill, {});
  const q = (query || '').trim();
  if (!q) return;
  const target = /^\s*search\b/i.test(q) ? q.split('|')[0].trim() : q;
  if (!target) return;
  if ($('#sql')) $('#sql').value = target;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  setDrillCrumb(target);
  runQuery();
}

// --- unités des métriques (pour des axes/valeurs lisibles) ---
const UNITS = { cpu_pct: '%', mem_pct: '%', swap_pct: '%', disk_root_pct: '%', temp_c: 'C', load1: '', net_rx_bps: 'B', net_tx_bps: 'B' };

function fmtBytes(n) { n = Number(n) || 0; const u = ['o', 'Ko', 'Mo', 'Go']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i] + '/s'; }

// déduit la métrique (donc l'unité) du nom de colonne OU du name='...' de la requête
function unitKeyFor(cols, query) {
  const last = cols[cols.length - 1];
  if (UNITS[last] !== undefined) return last;
  const m = (query || '').match(/name\s*=\s*'(\w+)'/);
  return m && UNITS[m[1]] !== undefined ? m[1] : null;
}

function fmtVal(key, v) {
  if (v === null || v === undefined) return '-';
  if (key === null) return String(v);
  if (key === 'net_rx_bps' || key === 'net_tx_bps') return fmtBytes(v);
  const u = UNITS[key];
  return u ? `${v} ${u}` : String(v);
}

function timelineEl(results) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const span = 3600, map = new Map();
  // par bucket : compte + sévérité max -> barre colorée (bleu sev1 -> rouge sev4, façon Splunk)
  results.forEach(r => { const b = Math.floor(r.ts / span) * span; const e = map.get(b) || { c: 0, s: 1 }; e.c++; e.s = Math.max(e.s, Math.min(4, r.severity || 1)); map.set(b, e); });
  const buckets = [...map.entries()].sort((a, b) => a[0] - b[0]);
  const W = 900, H = 120, pad = 26, n = buckets.length, max = Math.max(1, ...buckets.map(b => b[1].c));
  const svg = mk('svg'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('class', 'tlsvg');
  const bw = (W - 2 * pad) / Math.max(1, n);
  buckets.forEach(([b, e], i) => {
    const h = (e.c / max) * (H - 2 * pad), x = pad + i * bw, y = H - pad - h;
    const rect = mk('rect'); rect.setAttribute('x', x + 1); rect.setAttribute('y', y); rect.setAttribute('width', Math.max(1, bw - 2)); rect.setAttribute('height', h); rect.setAttribute('fill', CSSV('--sev' + e.s, '#2dd4bf'));
    svg.appendChild(rect);
  });
  const ax = mk('path'); ax.setAttribute('d', `M${pad},${H - pad} L${W - pad},${H - pad}`); ax.setAttribute('stroke', CSSV('--bd', '#16202e')); ax.setAttribute('fill', 'none'); svg.appendChild(ax);
  const txt = (x, y, s, a) => { const e = mk('text'); e.setAttribute('x', x); e.setAttribute('y', y); e.setAttribute('fill', CSSV('--mut', '#8aa0b4')); e.setAttribute('font-size', '10'); if (a) e.setAttribute('text-anchor', a); e.textContent = s; svg.appendChild(e); };
  if (n) { txt(pad, H - 8, fmtMaybeTime(buckets[0][0])); txt(W - pad, H - 8, fmtMaybeTime(buckets[n - 1][0]), 'end'); txt(3, pad, String(max)); }
  // (la timeline FTS Explore n'expose plus le zoom-temporel par drag/clic : la fenêtre se règle via le picker local #qrange)
  attachTip(svg, W, vx => { const i = Math.floor((vx - pad) / bw); return (i >= 0 && i < buckets.length) ? `${fmtMaybeTime(buckets[i][0])} : ${buckets[i][1].c}` : ''; });
  return svg;
}

// crée une action ban_ip (en attente d'approbation, dry-run). host optionnel = cible l'agent de cet
// hôte (sinon action non assignée, réclamée par le 1er agent qui poll). cf actions_pending côté daemon.
async function banIp(ip, host) {
  if (!ip || !(await confirmModal(`Créer une action ban_ip ${ip} ?${host ? ' (hôte ' + host + ')' : ''} (en attente d'approbation, dry-run)`, { okText: 'Créer' }))) return;
  const body = { kind: 'ban_ip', target: ip, dry_run: true, reason: 'depuis la recherche' };
  if (host) body.host = host;
  const j = await apiSend('/actions', 'POST', body);
  toast(j.error ? ('Erreur : ' + j.error) : "Action créée (en attente) - onglet Réponse pour l'approuver.", j.error ? 'bad' : 'ok');
  if (!j.error && typeof loadActions === 'function') loadActions();
}

// body-fetch mail : lit le corps COMPLET d'un message (admin + audite cote serveur), rendu isole.
async function mailBody(account, folder, fileid) {
  try {
    const r = await fetch('/api/mail/body', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ account, folder, id: fileid }) });
    const j = await r.json();
    if (!r.ok || j.error) { toast('Mail complet : ' + (j.error || ('HTTP ' + r.status)), 'bad'); return; }
    mailBodyView(j);
  } catch (e) { toast('Erreur : ' + e.message, 'bad'); }
}

// affichage isole : metadata + texte + HTML dans une iframe sandbox + CSP (anti-XSS / anti-tracking)
function mailBodyView(d) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal mailview';
  const onKey = e => { if (e.key === 'Escape') close(); };
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  document.addEventListener('keydown', onKey);
  const hdr = Object.entries(d.headers || {}).map(([k, v]) => `<div><b>${esc(k)}</b>: ${esc(String(v))}</div>`).join('');
  box.innerHTML = `<h3>${esc(d.subject || '(sans sujet)')}</h3>`
    + `<div class="mailmeta">de <b>${esc(d.from || '')}</b> &rarr; ${esc(d.to || '')} &middot; ${esc(d.account || '')}/${esc(d.folder || '')} &middot; ${esc(d.date || '')}</div>`
    + (hdr ? `<div class="mailhdr">${hdr}</div>` : '')
    + `<div class="mailsec">Texte</div><pre class="mailtext"></pre>`
    + `<div class="mailsec">HTML (rendu isolé)</div><div class="mailhtmlwrap"></div>`
    + `<div class="modal-act"><button type="button" class="m-cancel">Fermer</button></div>`;
  box.querySelector('.mailtext').textContent = d.text || '(vide)';
  if (d.html) {
    const ifr = document.createElement('iframe'); ifr.className = 'mailhtml'; ifr.setAttribute('sandbox', '');
    ifr.srcdoc = `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><base target="_blank">${d.html}`;
    box.querySelector('.mailhtmlwrap').appendChild(ifr);
  } else {
    box.querySelector('.mailhtmlwrap').textContent = '(pas de partie HTML)';
  }
  box.querySelector('.m-cancel').onclick = close;
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
}

function currentFrom() {
  if (S.zoomRange) return S.zoomRange.from;
  const r = Number(($('#range') && $('#range').value) || 0);
  return r > 0 ? Math.floor(Date.now() / 1000) - r : 0;
}

function currentTo() { return S.zoomRange ? S.zoomRange.to : 0; }

function setZoom(a, b) {
  const from = Math.floor(Math.min(a, b)), to = Math.ceil(Math.max(a, b));
  if (to - from < 1) return;
  S.zoomRange = { from, to }; updateZoomBadge(); rerenderZoom(); if (typeof updateRangeBtn === 'function') updateRangeBtn();
}

function clearZoom() { S.zoomRange = null; updateZoomBadge(); rerenderZoom(); if (typeof updateRangeBtn === 'function') updateRangeBtn(); }

function rerenderZoom() {
  refresh(); loadDashboard();
  if (S.lastResult && $('#sql') && $('#sql').value.trim()) runQuery();
}

function updateZoomBadge() {
  let el = $('#zoombadge');
  if (!el) {
    const tools = document.querySelector('.hdr-tools'); if (!tools) return;
    el = document.createElement('button'); el.id = 'zoombadge'; el.className = 'zoombadge'; el.type = 'button';
    el.title = 'Reinitialiser le zoom'; el.onclick = clearZoom; tools.insertBefore(el, tools.firstChild);
  }
  const f = t => new Date(t * 1000).toLocaleTimeString(LOC, { hour: '2-digit', minute: '2-digit', ...tzOpts() });
  if (S.zoomRange) { el.hidden = false; el.innerHTML = `zoom ${f(S.zoomRange.from)}-${f(S.zoomRange.to)} ${ic('x')}`; }
  else el.hidden = true;
}

// drag-select horizontal sur un graphe SVG -> zoom temporel (xToTime: x viewBox -> timestamp)
function attachZoom(svg, W, xToTime) {
  const NS = 'http://www.w3.org/2000/svg';
  let x0 = null, rectEl = null;
  const vbX = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
  if (timeZoomEnabled()) svg.style.cursor = 'ew-resize';   // pas d'appât de drag-zoom hors Dashboards (Explore)
  svg.addEventListener('mousedown', e => {
    if (!timeZoomEnabled()) return;                         // drag-select de zoom = Dashboards uniquement
    x0 = vbX(e); rectEl = document.createElementNS(NS, 'rect');
    rectEl.setAttribute('y', 0); rectEl.setAttribute('height', '100%');
    rectEl.setAttribute('fill', CSSV('--acc', '#2dd4bf')); rectEl.setAttribute('opacity', '0.18');
    svg.appendChild(rectEl); e.preventDefault();
  });
  svg.addEventListener('mousemove', e => { if (x0 == null || !rectEl) return; const x1 = vbX(e); rectEl.setAttribute('x', Math.min(x0, x1)); rectEl.setAttribute('width', Math.abs(x1 - x0)); });
  // drag-zoom = DASHBOARDS uniquement (sur Explore le picker local #qrange fait foi).
  const end = e => { if (x0 == null) return; const x1 = vbX(e); const a = Math.min(x0, x1), b = Math.max(x0, x1); x0 = null; if (rectEl) { rectEl.remove(); rectEl = null; } if (b - a > 4 && timeZoomEnabled()) { svg._zoomed = true; setZoom(xToTime(a), xToTime(b)); } };
  svg.addEventListener('mouseup', end); svg.addEventListener('mouseleave', end);
}

function tipShow(text, e) {
  if (!S._charttip) { S._charttip = document.createElement('div'); S._charttip.id = 'charttip'; document.body.appendChild(S._charttip); }
  const t = S._charttip; t.textContent = text; t.hidden = false;
  const pad = 14, w = t.offsetWidth, h = t.offsetHeight;
  let x = e.clientX + pad, y = e.clientY + pad;
  if (x + w > innerWidth) x = e.clientX - w - pad;
  if (y + h > innerHeight) y = e.clientY - h - pad;
  t.style.left = x + 'px'; t.style.top = y + 'px';
}

function tipHide() { if (S._charttip) S._charttip.hidden = true; }

// dataAt(vbX) -> texte de l'infobulle pour cette position X (ou '' = rien)
function attachTip(svg, W, dataAt) {
  const vbX = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
  svg.addEventListener('mousemove', e => { const s = dataAt(vbX(e)); if (s) tipShow(s, e); else tipHide(); });
  svg.addEventListener('mouseleave', tipHide);
}

// ============ EXPLORE : fenêtre glissante + requête interactive annulable (budget 60 s) ============
// La boîte EXPLORE (textarea GXQL + Exécuter) est une requête DÉLIBÉRÉE -> budget interactif 60 s côté
// daemon (interactive:true) + annulable (qid + POST /api/cancel). À NE PAS confondre avec les PANNEAUX
// (/api/panels/{id}/data, fenêtre glissante côté serveur, budget auto 5 s) : chemin séparé, intact.
//
// Fenêtre temporelle GLISSANTE propre à l'Explore (#qrange, piloté par le picker #qrangepick — même
// design que le picker Dashboard) : recalculée À CHAQUE exécution (from = now - window, to = 0).
// "Tout" -> from=0. L'intervalle absolu / zoom figé (zoomRange) reste prioritaire.
function exploreWindowSecs() { const s = $('#qrange'); return s ? (Number(s.value) || 0) : 86400; }

function exploreFrom() {
  if (S.zoomRange) return S.zoomRange.from;                   // zoom drag-select sur un graphe = prioritaire
  const w = exploreWindowSecs();
  return w > 0 ? Math.floor(Date.now() / 1000) - w : 0;   // glissant depuis maintenant ; "Tout" (0) -> from=0
}

function exploreTo() { return S.zoomRange ? S.zoomRange.to : 0; }

function nextQid() {
  try { if (typeof crypto !== 'undefined' && crypto.randomUUID) return 'qx-' + crypto.randomUUID(); } catch (e) {}
  return 'qx-' + Date.now().toString(36) + '-' + (++S._qidSeq);
}

function exploreSig(query, isSoql, limit, offset) {
  return JSON.stringify({
    q: query, s: !!isSoql, w: exploreWindowSecs(),
    z: S.zoomRange ? [S.zoomRange.from, S.zoomRange.to] : 0,
    l: (limit !== undefined && limit !== null) ? limit : null, o: offset || 0,
  });
}

// abort + /api/cancel best-effort de la requête en vol (clic STOP ou supersession par une autre requête).
function cancelInflight() {
  const inf = S.exploreInflight;
  if (!inf) return;
  S.exploreInflight = null;
  try { inf.ctrl.abort(); } catch (e) {}
  fetch('/api/cancel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ qid: inf.qid }) }).catch(() => {});
  setRunning(false);
}

function stopExplore() { if (!S.exploreInflight) return; cancelInflight(); flashStopped($('#qprog')); $('#qstats').textContent = 'Annulé'; renderQBadge(null); }

// indicateur "en cours" : bouton STOP visible + bouton Exécuter grisé pendant l'exécution.
function setRunning(on) {
  const stop = $('#qstop'); if (stop) stop.hidden = !on;
  const prog = $('#qprog'); if (prog) prog.hidden = !on;   // FIX 4 : ligne fine au-dessus du tableau
  const run = $('#run'); if (run) { run.classList.toggle('running', on); run.setAttribute('aria-busy', on ? 'true' : 'false'); }
}

// P11.9-c — CE QUE « TRONQUÉ — AMPLEUR INCONNUE » VEUT DIRE QUAND ON FEUILLETTE. MESURÉ le 2026-08-22 sur
// le chemin du démon : une page atteinte par SAUT DIRECT (numéro de page = OFFSET, sans curseur) sur une
// fenêtre qui touche le tier froid est servie depuis l'union hydratée, PLAFONNÉE en lignes ; au-delà du
// plafond le serveur pose `stats.truncated` sans pouvoir chiffrer l'écart. Le badge disait alors « le
// compte affiché est un plancher » — une phrase de TOTAL sur une page de PARCOURS, illisible pour qui ne
// connaît pas l'infrastructure. La navigation ◀ / ▶ (curseur) ne passe PAS par ce plafond : elle reste
// complète et continue. Le rendu nomme donc ce qui s'est passé et comment continuer, selon le contexte.
// Pure (texte + titre) -> tenue par le harnais ESM.
function truncationBadge(stats, navigation) {
  const ec = stats.topn_ecartes, tot = stats.topn_total;
  if (Number.isFinite(ec) && Number.isFinite(tot) && tot > 0) {
    const pct = Math.round((ec / tot) * 100);
    return ['qb-trunc', `tronqué — ${ec.toLocaleString('fr-FR')} écartés (${pct} %)`,
      `Le compte affiché est un PLANCHER : ${ec.toLocaleString('fr-FR')} événement(s) écartés sur ${tot.toLocaleString('fr-FR')} par le plafond top-N du pré-agrégé.`
      + (stats.rollup_note ? '\n\n' + stats.rollup_note : '')];
  }
  if (navigation && navigation.keyset && navigation.saut) {
    return ['qb-trunc', 'page sautée — contenu partiel',   // libellé STATIQUE : traduisible par le lexique ; le numéro de page est dans la ligne d'état
      `Cette page a été demandée par son NUMÉRO (saut direct). Au-delà de ce que le serveur peut matérialiser en une fois, une page sautée n'est ni complète ni garantie continue, et le total n'est pas recompté.\n`
      + `Les flèches ◀ / ▶ parcourent TOUT le résultat par curseur, sans ce plafond : revenez en arrière avec ◀ (ou à la page 1), puis avancez avec ▶. Pour atteindre une zone lointaine sans sauter, resserrez la fenêtre temporelle ou affinez la requête.`
      + (stats.rollup_note ? '\n\n' + stats.rollup_note : '')];
  }
  if (navigation && navigation.keyset) {
    return ['qb-trunc', 'page partielle — plafond de lignes du serveur',
      `Le serveur a rendu moins de lignes que cette page n'en demande, sans pouvoir mesurer ce qui manque (plafond de lignes ou de matérialisation atteint). ◀ / ▶ restent fiables ; si ce badge apparaît à CHAQUE page, la taille de page dépasse le plafond du serveur : choisissez une page plus petite.`
      + (stats.rollup_note ? '\n\n' + stats.rollup_note : '')];
  }
  return ['qb-trunc', 'tronqué — ampleur inconnue',
    "Résultat INCOMPLET : le serveur a atteint un plafond (lignes, matérialisation ou top-N) sans pouvoir mesurer ce qui manque — le compte affiché est un PLANCHER d'écart inconnu. Resserrez la fenêtre temporelle ou affinez la requête pour un résultat complet."
    + (stats.rollup_note ? '\n\n' + stats.rollup_note : '')];
}

// `P10.5-i` — CE QU'UN PANNEAU N'A PAS PU VOIR, DIT À L'ÉCRAN.
//
// LE DÉFAUT. Un panneau dont la fenêtre descend sous l'horizon de conservation rend une courbe VIDE ou
// écourtée, et la console l'affiche comme une courbe entière — ou, pire, écrit « aucune donnée sur la
// fenêtre », une phrase FAUSSE : il y a eu des données, elles sont sous l'horizon. Le démon publie
// désormais `stats.coverage` ; ces deux fabriques sont ce qui le fait arriver à l'écran. Sans elles,
// l'aveu atteindrait le navigateur et rien d'autre — le défaut déjà consigné « le démon avoue, la
// console n'écoute pas ».
//
// POURQUOI `renderQBadge` N'EST PAS RÉUTILISABLE : elle écrit dans `$('#qbadge')`, nœud UNIQUE de la
// page — l'appeler depuis un panneau déplacerait le badge d'Explore. Le précédent est tranché
// (`dataaccess.js` importe `truncationBadge`, pas `renderQBadge`).

// LE BADGE, POSÉ SEULEMENT QUAND LA FENÊTRE EST RÉELLEMENT PASSÉE SOUS L'HORIZON. `null` sinon — et
// c'est l'ANTI-FATIGUE, pas une économie : sur une base de trois jours où rien n'a jamais été purgé,
// douze panneaux sur douze porteraient le badge, et le panneau réellement amputé serait celui qu'on ne
// verrait plus. Rend un ÉLÉMENT et non un triplet (contrairement à `truncationBadge`) : le libellé est
// ainsi posé dans un puits d'affichage, donc VU par la garde du lexique et traduisible.
function coverageBadge(stats) {
  const c = stats && stats.coverage;
  if (!c || c.older_outside_window !== true) return null;
  const b = document.createElement('span');
  b.className = 'qb qb-approx';
  b.textContent = 'horizon atteint';
  // L'INFOBULLE PORTE AUSSI L'INSTANT DU CALCUL. Le démon publie `coverage.calcule_a` et le service SWR
  // rend une réponse MÉMORISÉE sans aucun prédicat de fraîcheur : un corps de trente heures se lit
  // autrement qu'un corps de maintenant, et rien à l'écran ne les distinguait.
  b.title = (c.notice || '')
    + (Number.isFinite(c.horizon_ts) ? '\n\nHorizon : ' + fmtTs(c.horizon_ts) : '')
    + (Number.isFinite(c.calcule_a) ? '\nCalculé le : ' + fmtTs(c.calcule_a) : '');
  return b;
}

// LE PLAFOND TOP-N D'UN PANNEAU OPAQUE, DIT À L'ÉCRAN. Le démon publie `provenance_non_derivee` et, quand
// le SQL nomme le pré-agrégé par dimension, un `rollup_note` disant que le compte affiché est un
// PLANCHER. Aucun module de la console ne lisait ces deux champs : l'aveu arrivait dans le navigateur et
// s'arrêtait là — le défaut « le démon avoue, la console n'écoute pas », recréé mot pour mot.
//
// LE BADGE NE PARAÎT QUE SUR LE SOUS-ENSEMBLE OÙ IL Y A QUELQUE CHOSE À DIRE, et c'est l'anti-fatigue :
// `provenance_non_derivee` est vrai sur TOUT panneau SQL brut (les courbes de métriques comprises, où il
// n'y a aucun plafond) ; seul `rollup_note` marque un plafond RÉEL. `renderQBadge` n'est pas réutilisable
// ici : elle écrit dans `$('#qbadge')`, nœud unique d'Explore.
function provenanceBadge(stats) {
  if (!stats || stats.provenance_non_derivee !== true || !stats.rollup_note) return null;
  const b = document.createElement('span');
  b.className = 'qb qb-approx';
  b.textContent = 'compte plancher';
  b.title = stats.rollup_note;
  return b;
}

// LES DEUX NŒUDS DE L'HORIZON, SÉPARÉS — et la séparation est imposée par un piège que ce dépôt nomme
// lui-même : `i18nWalk` ne remplace que sur l'égalité du nœud texte ENTIER après `trim()`. Un libellé
// concaténé avec sa date serait classé « dynamique » et son entrée de lexique naîtrait MORTE (c'est ce
// qui est arrivé à « (tronqué) »). Le libellé est donc un nœud à lui seul ; la date en est un autre.
//
// TROIS SORTIES, PARCE QUE LE DÉMON A TROIS CHOSES À DIRE ET QUE DEUX D'ENTRE ELLES SE CONFONDAIENT.
//   (1) horizon MESURÉ -> le libellé et sa date, deux nœuds ;
//   (2) le démon REFUSE de conclure (`portee_non_derivable` quand la requête ne nomme aucune table dont
//       la rétention soit connue — cas MESURÉ des panneaux `banned_ip`, livrés et semés ; ou
//       `horizon_non_mesure` quand le pool de lecture n'a pas pu être pris) -> UN nœud qui dit ce refus,
//       et AUCUNE date : on ne fabrique pas un horizon qu'on n'a pas. Rendre `null` ici laissait la
//       console afficher « aucune donnée sur la fenêtre » toute seule, c'est-à-dire CONCLURE à l'absence
//       là où le démon écrit noir sur blanc « on ne sait pas jusqu'où cette réponse a pu voir » ;
//   (3) aucun aveu du tout (binaire antérieur, surface non couverte) -> `null`, affichage d'avant.
function coverageHorizonNodes(stats) {
  const c = stats && stats.coverage;
  if (!c) return null;
  if (Number.isFinite(c.horizon_ts)) {
    return [
      document.createTextNode("l'horizon de conservation s'arrête ici"),
      document.createTextNode(' — ' + fmtTs(c.horizon_ts)),
    ];
  }
  if (!c.reason) return null;
  return [document.createTextNode("jusqu'où ce panneau a pu voir n'est pas établi")];
}

// BADGE de transparence (confiance SOC) : l'analyste DOIT voir si le chiffre vient d'un rollup, et s'il
// est approximatif/tronqué, vs un scan brut exact. stats.served_from "rollup"|"raw" + approx + truncated.
// `navigation` (optionnel) = { keyset, saut, page } : le contexte de feuilletage, qui change ce que
// « tronqué » veut dire (cf. truncationBadge).
function renderQBadge(stats, navigation) {
  const el = $('#qbadge'); if (!el) return;
  const parts = [];
  if (stats && stats.served_from === 'rollup') {
    parts.push(['qb-rollup', '⚡ rollup', 'Servi depuis un rollup pré-agrégé (rapide) — pas un scan brut']);
    if (stats.approx) parts.push(['qb-approx', '~approx', "Valeur approximative (issue d'un rollup tronqué)"]);
  } else if (stats && stats.served_from === 'raw') {
    parts.push(['qb-raw', 'brut', 'Données brutes (scan, non pré-agrégé) — exact']);
  }
  // TRONQUÉ : dire l'AMPLEUR, pas seulement le mot. « tronqué (top 50) » ne permettait pas de savoir s'il
  // manque trois valeurs ou seize fois le compte affiché (MESURÉ : jusqu'à x16,4 sur le banc). Quand le
  // serveur a pu CHIFFRER ce que le plafond écarte (stats.topn_ecartes/topn_total), on l'affiche ; sinon on
  // dit que l'ampleur est INCONNUE — jamais un chiffre qu'on n'a pas.
  if (stats && stats.truncated) parts.push(truncationBadge(stats, navigation));
  el.replaceChildren(...parts.map(([cls, text, title]) => {
    const b = document.createElement('span'); b.className = 'qb ' + cls; b.textContent = text; b.title = title; return b;
  }));
  el.hidden = parts.length === 0;
}

// message propre à partir d'une exception levée par le fetch (annulation / budget / réponse vide).
function explainErr(e) {
  if (e && e.name === 'AbortError') return 'Annulé';
  if (e && e.code === 'empty') return 'Trop lourd même sur 60s — resserre la fenêtre';
  const m = (e && e.message) ? e.message : String(e);
  if (/budget|dépass|trop lourd|too heavy|timeout|deadline/i.test(m)) return 'Trop lourd même sur 60s — resserre la fenêtre';
  return 'erreur : ' + m;
}

// erreur SERVEUR (j.error) : annulation/budget -> ligne de stats lisible ; sinon boîte rouge (existant).
function showQError(serverMsg) {
  renderQBadge(null);
  if (typeof showQExport === 'function') showQExport(false);
  const m = serverMsg || '';
  if (/annul/i.test(m)) { $('#qresult').replaceChildren(); $('#qstats').textContent = 'Annulé'; return; }
  if (/budget|dépass|trop lourd|too heavy|timeout|deadline/i.test(m)) { $('#qresult').replaceChildren(); $('#qstats').textContent = 'Trop lourd même sur 60s — resserre la fenêtre'; return; }
  $('#qresult').replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + m }));
  $('#qstats').textContent = '';
}

// `P10.5-g` — LE REMÈDE MACHINE EST APPLIQUÉ, PAS SEULEMENT AFFICHÉ.
// Un refus de curseur froid publie `restart_without_cursor` : c'est une CONDUITE adressée au
// programme, pas une phrase adressée à l'humain. Sans l'appliquer, la table des curseurs garde le
// curseur MORT et « Suivant » le rejoue indéfiniment — le message s'affiche et rien ne bouge, si
// bien que l'analyste voit un produit bloqué là où le démon lui a dit exactement quoi faire. Le
// geste existait DÉJÀ ailleurs dans la console (les panneaux remettent `cursors` à `[null]` quand
// leur fenêtre change) ; il manquait sur ce chemin, et c'est tout le défaut.
// LA REPRISE EST BORNÉE À UNE PAR PAGE SERVIE : le drapeau se lève ici et retombe dès qu'une page
// est rendue, si bien que deux refus CONSÉCUTIFS sans page entre eux ne peuvent pas boucler, tandis
// qu'un refus survenant plus loin dans le parcours redonne droit à une reprise.
// LA FENÊTRE EST REGELÉE, PAS EFFACÉE : reprendre, c'est ouvrir un parcours NEUF, et « un parcours,
// une fenêtre » vaut aussi pour celui-là. L'effacer ferait recalculer la fenêtre à CHAQUE page —
// exactement ce que ce chantier a fermé.
// ET LA REPRISE SE DIT : une page qui repart de 1 sans un mot serait un résultat juste rendu comme
// s'il n'était rien arrivé. Le motif machine du démon est repris tel quel dans la ligne d'état.
function reprendreSansCurseur(j) {
  if (!j || j.restart_without_cursor !== true) return false;
  if (S.evState.repriseSansCurseurFaite) return false;
  S.evState.repriseSansCurseurFaite = true;
  S.evState.repriseAnnonce = j.reason ? String(j.reason) : true;   // le démon nomme TOUJOURS sa cause ; sans elle on annonce la reprise sans en inventer une
  S.evState.cursors = [null];
  S.evState.page = 0;
  S.evState.win = { from: exploreFrom(), to: exploreTo() };
  return true;
}

// ==============================================================================================
// `P11.18-r` — LA BORNE HAUTE EST UN ARGUMENT DE L'APPELANT, ET SON DÉFAUT N'HÉRITE DE RIEN.
//
// CE QUI ÉTAIT ÉCRIT ICI, ET CE QUE ÇA FABRIQUAIT. `body.to = exploreTo()`, POSÉ SANS CONDITION :
// toute requête passant par ce fabricant était bornée en haut par `S.zoomRange`, l'intervalle absolu
// réglé dans l'Explore ou les tableaux de bord. Les vues qui n'ont jamais touché à cet état en
// héritaient donc en silence — mesuré le 2026-08-25 : les cinq requêtes de la prévention des fuites
// partaient bornées pendant que leur barre annonçait « toute la rétention », et le sous-panneau
// d'accès opérateur (`web/multitenant.js`) l'héritait sans même le savoir. La vue disait une chose,
// la requête en faisait une autre.
//
// LA DÉCISION, ET SA RAISON. Une requête N'HÉRITE PAS d'un intervalle réglé dans une AUTRE vue. Deux
// vues qui ne partagent ni barre ni libellé ne partagent pas une fenêtre ; hériter en silence est ce
// qui rend une vue incapable de dire ce qu'elle envoie. La borne haute devient donc un argument
// (`opts.to`), dont le défaut est `0` — aucune borne. Les vues qui RÈGLENT cet intervalle et qui
// l'AFFICHENT (l'Explore, par son `#zoombadge` et son libellé de plage) le passent explicitement ;
// les autres ne le reçoivent plus.
//
// CE QUI N'EST PAS FAIT, ET POURQUOI. On ne filtre JAMAIS côté navigateur pour compenser une borne
// que la route ne porte pas : l'ordre étant décroissant, cela viderait les premières pages et ferait
// compter au total des lignes cachées — c'est-à-dire rendrait un refus comme une absence.
// LA BORNE BASSE reste ce qu'elle était : elle est DÉJÀ un argument (`fromOverride`), et ses deux
// appelants hors Explore la posent tous les deux. Aucune vue n'en hérite, mesuré le même jour ; son
// défaut hérite pourtant encore, et c'est un reste NOMMÉ plutôt que corrigé au passage.
// ==============================================================================================
async function runQ(query, isSoql, fromOverride, limit, offset, opts) {
  opts = opts || {};
  const body = isSoql ? { soql: query } : { sql: query };
  body.from = (fromOverride !== undefined ? fromOverride : exploreFrom());
  body.to = (opts.to !== undefined ? opts.to : 0);
  if (limit !== undefined && limit !== null) {
    body.limit = limit;
    // KEYSET (#28) : pagination par CURSEUR (parcours intégral, sans le cap 10 000 qui cachait des événements).
    // `opts.keyset` -> on envoie keyset:true + le curseur `{ts,id}` de la page précédente (absent = première page) ;
    // sinon offset historique (panneaux/table). Le serveur renvoie next_cursor/has_more (au lieu de total/offset).
    if (opts.keyset) { body.keyset = true; if (opts.cursor) body.cursor = opts.cursor; else if (opts.offset) body.offset = opts.offset; }   // curseur (séquentiel) OU offset (saut à une page)
    else { body.offset = offset || 0; }
  }
  body.interactive = true;            // Explore = requête délibérée -> budget 60 s (les PANNEAUX restent SANS -> 5 s)
  if (opts.qid) body.qid = opts.qid;  // annulable via POST /api/cancel {qid}
  const r = await fetch('/api/query', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body), signal: opts.signal,
  });
  const t = await r.text().catch(() => '');   // texte d'abord -> gère réponse vide/tronquée (timeout proxy)
  if (!t) { const e = new Error('réponse vide du serveur (timeout proxy ou requête trop lourde ?)'); e.code = 'empty'; throw e; }
  try { return JSON.parse(t); } catch { throw new Error('réponse non-JSON (tronquée ? timeout ?) : ' + t.slice(0, 120)); }
}

// LA REPRÉSENTATION ELLE-MÊME, SANS LA PORTE. Un seul appelant a le droit de la prendre : le SONDAGE
// (`rendreEnSonde`), qui doit observer ce que la représentation FAIT et non ce que la porte laisse
// passer — et qui, passant par la porte, s'appellerait lui-même sans fin. Tout le reste passe par
// `vizElement`.
function vizSansPorte(mode, cols, rows, query, drill) {
  if (mode === 'stat') return statEl(cols, rows, query, drill);
  if (mode === 'bar') return barEl(cols, rows, query, drill);
  if (mode === 'line') return lineEl(cols, rows, query, drill);
  // #54 — types de panneaux supplémentaires (parité Grafana/Splunk). Canvas/SVG inline, ZÉRO lib externe
  // (CSP bloque les CDN + charte vendor-free). Chacun consomme le même {columns,rows} GXQL.
  if (mode === 'gauge') return gaugeEl(cols, rows, query, drill);
  if (mode === 'pie' || mode === 'donut') return pieEl(cols, rows, query, drill, mode === 'donut');
  if (mode === 'heatmap') return heatmapEl(cols, rows, query, drill);
  if (mode === 'histogram') return histogramEl(cols, rows, query, drill);
  return tableEl(cols, rows, query, drill);
}

// `P11.18-p` — LA PORTE. Une représentation qui ne peut pas exprimer CETTE donnée n'est pas offerte
// pour elle. Ce n'est ni un drapeau ni un avertissement posé à côté du graphe : le graphe n'est pas
// tracé, et ce qui prend sa place DIT la colonne, le compte et la valeur qui l'ont empêché.
// LA PORTE EST ICI, au point où une représentation est CHOISIE pour un jeu de colonnes, et non dans
// chacune des représentations : c'est le seul endroit que tout appelant traverse — le panneau réglé,
// l'éditeur de requête, et l'aperçu d'un instantané partagé, qui n'a AUCUNE barre de réglage. Une
// représentation posée demain est couverte sans qu'on l'écrive, parce que la porte ne connaît aucun
// type de graphe : elle DEMANDE au sondage ce que celui-ci a répondu.
// LA SECONDE PORTE, ET ELLE NE LIT PAS LA DONNÉE : ELLE LIT LE RENDU (`P11.18-p`). La première décide
// SUR LA DONNÉE — une fente ramenée à un nombre que la colonne ne porte pas. Elle ne peut pas voir le
// cas où la donnée est PARFAITEMENT valide et où la représentation ne dessine RIEN quand même : mesuré
// le 2026-08-27, `pie` et `donut` sur trois lignes dont les valeurs sont toutes nulles — ou négatives —
// laissaient passer la première porte (la colonne EST numérique) puis affirmaient « aucune donnée » sur
// des lignes SERVIES. C'est l'absence affirmée à la place d'un refus, exactement l'instance que la clé
// énumère. La mesure qui tranche ne peut pas venir de la donnée : elle vient du RENDU LUI-MÊME, compté
// avec la MÊME fonction que le sondage (`marquesDe`, un seul écrivain de la notion de marque). Aucun
// type de graphe n'est nommé : une représentation posée demain qui ne dessinerait rien sur des lignes
// servies est refusée sans qu'on l'écrive, et celle qui dessine ne paie qu'un parcours de son arbre.
// CE QUE CETTE PORTE NE VOIT PAS, ÉCRIT PLUTÔT QUE TU : elle constate l'ABSENCE de marque, pas son
// INVISIBILITÉ. `marquesDe` compte une déclaration de fond même quand elle vaut « transparent » —
// mesuré le 2026-08-27, une grille de chaleur dont toutes les valeurs sont nulles rend donc ses cellules
// (vides à l'œil) et n'est PAS refusée. Fermer ce cas-là demande de juger l'encre peinte, ce que ni ce
// module ni son banc ne savent faire ; c'est un reste nommé, pas un reste caché.
function vizElement(mode, cols, rows, query, drill) {
  const refus = refusDeRepresentation(mode, cols, rows);
  if (refus) return noeudDeRefus(refus);
  const figure = vizSansPorte(mode, cols, rows, query, drill);
  const muette = refusDUneFigureMuette(mode, cols, rows, figure);
  return muette ? noeudDeRefus(muette) : figure;
}

// ==============================================================================================
// `P11.18-a` — RÉGLER UN GRAPHE : CE QUI PORTE L'ABSCISSE, CE QUI PORTE L'ORDONNÉE.
//
// LA RÈGLE QUI EXISTAIT DÉJÀ, MESURÉE PAR MUTATION le 2026-08-25 (on remplace les valeurs d'UNE
// colonne du résultat, on re-rend, et on regarde si le rendu change : ce qui ne change pas n'est pas
// lu). Elle est UNIQUE et POSITIONNELLE pour les neuf représentations — PREMIÈRE colonne = dimension
// (abscisse), DERNIÈRE colonne = valeur (ordonnée) — et les colonnes du MILIEU sont IGNORÉES, sauf
// par `heatmap` (2e colonne = colonnes de la grille, dès 3 colonnes) et par `table` (qui les rend
// toutes). Aucun NOM de colonne n'entre dans cette règle : les noms ne servent qu'à l'unité
// (`unitKeyFor`) et à la suppression du drill (`DIMENSIONLESS`). `stats count by host, source` rend
// donc `[host, source, count]`, et `source` est jeté en silence par barres, courbe et camembert.
//
// CE QUE CETTE MESURE DÉCIDE, et c'est la question que la clé posait : puisque la règle est DÉJÀ
// dérivée de la POSITION et PARTAGÉE par toutes les représentations, le réglage n'a rien à remplacer.
// Il se pose AU-DESSUS : il REMET AU GRAPHE les colonnes dans l'ordre voulu — `[abscisse,
// (2e dimension), ordonnée]` — et la règle positionnelle fait le reste. Une représentation posée
// demain hérite du réglage sans le savoir, parce qu'elle héritera de la règle que tout ce module
// partage. `vizElement` n'est PAS touché : un appelant qui ne passe pas de réglage rend exactement ce
// qu'il rendait, et cette non-modification en est la preuve la plus courte.
//
// CE QUE CE BLOC NE FAISAIT PAS, ET QUI EST FAIT DEPUIS : il ne redressait PAS le chemin PAR DÉFAUT.
// Mesuré le même jour sur banc, sans aucun réglage : `gauge` sur une colonne textuelle affiche
// « 0 / 1 » (un zéro FABRIQUÉ), `line` écrase toutes les abscisses non numériques sur un point unique,
// `bar` trace toutes ses barres à 0 % de large tout en imprimant le texte à côté, et `pie` répond
// « aucune donnée » alors que les lignes existent — une ABSENCE affirmée à la place d'un refus. Seul
// `histogram` disait alors « aucune donnée numérique », et son honnêteté n'était que PARTIELLE : sur une
// colonne MÉLANGÉE il rendait la valeur textuelle en barre de hauteur zéro comme les autres.
//
// CE QUE `P11.18-p` A FERMÉ, ET CE QU'IL AVAIT LAISSÉ OUVERT EN SE CROYANT CLOS. La PREMIÈRE porte, dans
// `vizElement`, refuse une représentation qui ramènerait une fente à un nombre que la colonne servie ne
// porte pas : le chemin de la fente NON NUMÉRIQUE est fermé, et c'est le seul que la phrase qui vivait
// ici couvrait — elle disait pourtant « ce chemin », au singulier, ce qui était plus large que sa mesure.
// MESURÉ LE 2026-08-27 : sur une colonne NUMÉRIQUE dont les valeurs sont toutes nulles — ou négatives —
// la première porte laisse passer, et `pie` comme `donut` répondaient « aucune donnée » sur TROIS lignes
// servies. C'est mot pour mot l'instance que la clé énumère, restée ouverte pendant que ce commentaire
// la déclarait close. La SECONDE porte la ferme, et elle ne nomme aucun type : une représentation qui
// TRACE et qui, sur ce rendu-là, ne pose AUCUNE marque rend un refus qui dit ce qui manque.
// CE QUE LE REDRESSEMENT COÛTE AUX PANNEAUX EXISTANTS : sur une donnée dont les fentes sont valides ET
// dont l'ordonnée porte au moins une valeur strictement positive, les neuf représentations rendent un
// balisage byte-identique, porte comprise. La borne de cette phrase est celle du témoin qui l'établit :
// il joue un jeu FABRIQUÉ, il ne dit rien des panneaux SEMÉS par le démon, dont les requêtes vivent hors
// de `web/`. CE QUI RESTE OUVERT, ÉCRIT PLUTÔT QUE TU : une colonne numérique LÀ OÙ ELLE EST REMPLIE mais
// trouée (`null`, chaîne vide) franchit les deux portes — `profilDeColonne` saute les vides avant de
// conclure — et `Number(v) || 0` dessine ces trous à ZÉRO (mesuré le 2026-08-27 : `bar` sur
// [['a',5],['b',null],['c',7]] rend trois barres, celle du milieu à 0 % de large, « - » imprimé à côté).
// Ce n'est pas la même faute, et elle n'est pas fermée ici. Le refus ci-dessous, lui, reste attaché au
// CHOIX : il porte en plus le plafond de cardinalité, qui juge la LISIBILITÉ et non la vérité, et que la
// porte n'impose donc pas par défaut.
const PLAFOND_CARDINALITE_ABSCISSE = 200;   // au-delà, une marque occupe moins de 3 unités sur les 580
                                            // utiles du canevas de 640 que ces représentations partagent :
                                            // les marques fusionnent. UN seul plafond, le même pour toutes,
                                            // pour qu'une représentation posée demain en hérite aussi.

// -- CE QU'UNE REPRÉSENTATION LIT, DEMANDÉ À LA REPRÉSENTATION ELLE-MÊME ------------------------
// Jamais à une liste écrite par type : on la rend sur un jeu FABRIQUÉ, on mute une colonne, on
// compare. Trois faits en sortent : quelles FENTES elle lit, si elle TRACE (une géométrie qui suit la
// valeur) ou si elle se contente de texte, et si son ordonnée doit être un NOMBRE.
// TÉMOIN DE CONTRÔLE INTÉGRÉ, sans quoi un zéro ne prouverait rien : on vérifie D'ABORD que deux
// ordonnées NUMÉRIQUES différentes bougent la géométrie. Si elles ne la bougent pas, la
// représentation ne trace pas (table, stat) et rien ne lui est reproché. C'est seulement une fois ce
// témoin positif obtenu que « deux ordonnées TEXTUELLES différentes produisent la MÊME géométrie »
// signifie quelque chose : la valeur n'est pas exprimée, elle est coercée — le graphe serait FAUX.
// Ce sondage est aussi ce qui rend le réglage indifférent aux types : ce qui est offert vient de ce
// que la représentation a répondu, pas d'une table écrite ici.
const SONDE_COLS = ['sonde_a', 'sonde_b', 'sonde_c'];
const SONDE_N1 = [[10, 4, 3], [20, 5, 9]];
const SONDE_N2 = [[10, 4, 7], [20, 5, 2]];
const SONDE_T1 = [[10, 4, 'pa'], [20, 5, 'qb']];
const SONDE_T2 = [[10, 4, 'rc'], [20, 5, 'sd']];
// `P11.18-p` — LA MÊME QUESTION, POSÉE À L'ABSCISSE. Elle demande TROIS lignes et des BORNES FIXES :
// deux lignes ne suffisent pas (une échelle qui normalise sur [min, max] pose toujours la première et
// la dernière au même endroit, donc rien ne bougerait et la sonde ne conclurait pas — mesuré le
// 2026-08-26, elle rendait `false` sur `line`) ; et bouger la PREMIÈRE ligne ferait parler une
// représentation qui lit la colonne 0 pour AUTRE CHOSE qu'une position — la jauge y lit son échelle,
// et elle s'allumait à tort. En ne mutant que le rang du MILIEU, la sonde ne répond « oui » que si la
// représentation PLACE ses lignes selon la valeur d'abscisse. Mesuré : `line` seule.
const SONDE_XN1 = [[10, 4, 3], [20, 5, 9], [100, 6, 1]];
const SONDE_XN2 = [[10, 4, 3], [90, 5, 9], [100, 6, 1]];
const SONDE_XT1 = [['pa', 4, 3], ['qb', 5, 9], ['rc', 6, 1]];
const SONDE_XT2 = [['sd', 4, 3], ['te', 5, 9], ['uf', 6, 1]];
// `P11.18-a` — LA QUESTION QUE TROIS FENTES NE SAVENT PAS POSER : cette représentation lit-elle AU-DELÀ
// des trois rangs que le réglage manipule ? Les fentes ci-dessus sont sondées sur TROIS colonnes ; une
// représentation qui en rendrait cinq répondrait EXACTEMENT la même chose, parce qu'il n'y a pas de
// quatrième rang à muter. On lui en donne donc CINQ et on mute les deux rangs du MILIEU qu'aucune fente
// ne désigne (le 3e et le 4e sur cinq). Si l'empreinte bouge, elle lit plus que les trois fentes — et le
// réglage n'a alors pas le droit de projeter sur trois rangs, sous peine de RETIRER des colonnes servies.
const SONDE_LARGE_COLS = ['sonde_a', 'sonde_b', 'sonde_c', 'sonde_d', 'sonde_e'];
const SONDE_LARGE = [[10, 4, 3, 7, 2], [20, 5, 9, 8, 6]];
const RANGS_HORS_FENTES = [2, 3];   // sur CINQ colonnes : ni la première, ni la deuxième, ni la dernière
// La GÉOMÉTRIE d'un rendu = ce qui place ou dimensionne une marque. Le TEXTE en est exclu : c'est lui
// qui rend un graphe faux crédible (une barre à 0 % qui affiche « rouge » juste à côté). Les marques
// CONSTANTES d'un rendu (le tracé d'une icône) ne gênent pas : le sondage ne lit jamais une géométrie
// seule, il COMPARE deux rendus, et ce qui ne dépend pas des données s'annule des deux côtés.
const ATTRS_GEOMETRIE = ['points', 'd', 'x', 'y', 'cx', 'cy', 'r', 'width', 'height'];
function marquesDe(n, out) {
  out = out || [];
  if (n && n.attributes) {
    const g = ATTRS_GEOMETRIE.map(a => n.attributes[a]).filter(v => v !== undefined);
    if (g.length) out.push(n.tagName + '|' + g.join(','));
    if (n.style && n.style.width) out.push(n.tagName + '|w=' + n.style.width);
    if (n.style && n.style.background) out.push(n.tagName + '|b=' + n.style.background);
  }
  for (const c of (n && n.children) || []) marquesDe(c, out);
  return out;
}
function empreinteDe(n) {
  if (!n) return '';
  const at = Object.keys(n.attributes || {}).sort().map(k => k + '=' + n.attributes[k]).join(',');
  return n.tagName + '[' + at + ']' + (n.textContent || '');
}
// `vizSansPorte` et non `vizElement` : le sondage mesure ce que la REPRÉSENTATION fait, et la porte
// qu'il alimente le rappellerait sans fin s'il la traversait (`P11.18-p`).
function rendreEnSonde(mode, rows, cols) { try { return vizSansPorte(mode, cols || SONDE_COLS, rows, '', ''); } catch (e) { return null; } }
const _sondages = new Map();
function sondage(mode) {
  if (_sondages.has(mode)) return _sondages.get(mode);
  const geo = rows => marquesDe(rendreEnSonde(mode, rows)).join(';');
  const trace = geo(SONDE_N1) !== geo(SONDE_N2);               // TÉMOIN POSITIF : la géométrie suit la valeur
  const ordonneeNumerique = trace && geo(SONDE_T1) === geo(SONDE_T2);
  // MÊME FORME, MÊME TÉMOIN POSITIF, sur l'autre fente (`P11.18-p`) : la représentation place-t-elle
  // ses lignes selon l'ABSCISSE, et si oui ramène-t-elle une abscisse textuelle à un nombre ?
  const placeParAbscisse = geo(SONDE_XN1) !== geo(SONDE_XN2);
  const abscisseNumerique = placeParAbscisse && geo(SONDE_XT1) === geo(SONDE_XT2);
  const ref = empreinteDe(rendreEnSonde(mode, SONDE_N1));
  const fentes = SONDE_COLS.map((_, k) => {
    const mut = SONDE_N1.map(r => r.map((v, j) => (j === k ? Number(v) + 500 : v)));
    return empreinteDe(rendreEnSonde(mode, mut)) !== ref;
  });
  // LA MÊME FORME, SUR CINQ COLONNES (`P11.18-a`) : la représentation lit-elle un rang qu'AUCUNE fente
  // ne désigne ? Le témoin positif est celui des fentes juste au-dessus — si muter un rang LU ne changeait
  // rien, l'empreinte ne mesurerait pas ce qu'on croit. Ici on mute les rangs du milieu d'un jeu à cinq :
  // `table`, qui rend toutes ses colonnes, répond OUI ; `heatmap`, qui n'en lit que trois, répond NON.
  const refLarge = empreinteDe(rendreEnSonde(mode, SONDE_LARGE, SONDE_LARGE_COLS));
  const litAuDelaDesFentes = RANGS_HORS_FENTES.some(k => {
    const mut = SONDE_LARGE.map(r => r.map((v, j) => (j === k ? Number(v) + 500 : v)));
    return empreinteDe(rendreEnSonde(mode, mut, SONDE_LARGE_COLS)) !== refLarge;
  });
  const s = { trace, ordonneeNumerique, placeParAbscisse, abscisseNumerique, fentes, litAuDelaDesFentes };
  _sondages.set(mode, s);
  return s;
}

// -- LE MAGASIN DU RÉGLAGE ---------------------------------------------------------------------
// Le store de préférences ADOSSÉ AU DÉMON (`prefs.js` -> `/api/prefs`, self-scoped, viewer+), et non
// `localStorage` en direct. TROIS RAISONS, dont une contrainte de fait :
// (1) le démon n'a AUCUNE colonne où loger un axe : `/api/panels/{id}` accepte titre, requête, viz,
//     fenêtre, visibilité, requête privée, drill, colonnes et hauteur — rien d'autre. `patchPanel` ne
//     peut donc pas porter ce réglage sans une capacité NOUVELLE du démon ;
// (2) `prefs.js` est DURABLE ET INTER-POSTES (le démon garde le blob) là où `localStorage` seul
//     perdrait le réglage au changement de navigateur — exactement la perte que la clé nomme ;
// (3) il MIROITE déjà dans `localStorage` : le stockage local est obtenu sans l'écrire deux fois, et
//     la console reste réglable hors ligne.
// CE QUE CE CHOIX COÛTE, écrit plutôt que tu : le réglage est PAR COMPTE, il n'est pas porté par le
// panneau partagé. Deux exploitants devant le même panneau peuvent voir deux axes. Le rendre commun
// exige une colonne au démon ; la capacité manque, elle est nommée ici plutôt que contournée.
// `P11.18-q` A TRANCHÉ CE COÛT PLUTÔT QUE DE LE LAISSER TACITE : le réglage appartient à la PERSONNE,
// et la vue le DIT dès que ce qu'elle montre s'écarte de ce que le panneau enregistré sert — voir
// `avisDeReglagePrive` plus bas. Ce commentaire seul ne rattrapait rien : il était vrai et INVISIBLE
// pour qui compose un tableau de bord pour son équipe.
// Le réglage retient des NOMS de colonne, pas des rangs : une requête ré-écrite qui garde la colonne
// garde le réglage, et une requête qui la retire produit un REFUS qui la nomme — là où un rang aurait
// silencieusement désigné une autre colonne.
const CLE_PREF_AXES = 'viz_axes';   // clé du blob de préférences ; tout en minuscules, comme les autres identifiants techniques du dépôt
const PLAFOND_REGLAGES_MEMORISES = 60;   // borne du blob de préférences ; le plus ancien inscrit sort.
function reglagesMemorises() { const o = prefGet(CLE_PREF_AXES, null); return (o && typeof o === 'object' && !Array.isArray(o)) ? o : {}; }
function reglageLu(cle) { const r = cle ? reglagesMemorises()[cle] : null; return (r && typeof r === 'object') ? r : null; }
function reglageEcrit(cle, r) {
  if (!cle) return;
  const tout = reglagesMemorises();
  if (!r || (!r.x && !r.y && !r.s)) delete tout[cle]; else tout[cle] = r;
  const cles = Object.keys(tout);
  while (cles.length > PLAFOND_REGLAGES_MEMORISES) delete tout[cles.shift()];
  prefSet(CLE_PREF_AXES, tout);
}
// La CLÉ d'un réglage : l'identité du panneau quand il y en a une, sinon la SIGNATURE des colonnes
// servies — Explore n'a pas d'objet persistant, et la FORME du résultat est ce qui s'y répète.
function cleDeReglage(idPanneau, cols) { return idPanneau ? ('p' + idPanneau) : ('c' + cols.join('\x1f')); }

// -- CE QUE LA REQUÊTE REND VRAIMENT -----------------------------------------------------------
// Un fait par colonne, LU SUR LES LIGNES SERVIES : rien n'est deviné d'un nom de champ ni d'un type
// de graphe. C'est de là, et de là seulement, que sortent les choix offerts et les refus.
// UNE SEULE DÉFINITION DE « CETTE LIGNE PORTE UNE VALEUR », lue par le profil de colonne, par les refus
// et par les figures qui comptent ce qu'elles laissent de côté. L'écrire deux fois laisse entrer un zéro
// FABRIQUÉ dans un compte de zéros MESURÉS : `Number(null)` et `Number('')` valent 0 et sont FINIS, si
// bien qu'une absence passait pour une valeur nulle lue — mesuré le 2026-08-27, et c'était exactement le
// grief que la première porte se fait à elle-même (« le zéro affirmerait une lecture qui n'a pas eu lieu »).
// CE QUE CE PRÉDICAT NE TRANCHE PAS, écrit plutôt que tu : une chaîne de BLANCS (`' '`) est ici une
// valeur, et `Number(' ')` vaut 0 — elle est donc lue comme un zéro. Le dire autrement demande de changer
// la définition que TOUT ce module partage, pas une phrase ; ce n'est pas fait ici.
function porteUneValeur(v) { return v !== null && v !== undefined && v !== ''; }
function profilDeColonne(nom, i, rows) {
  let nonVides = 0, nombres = 0; const vus = new Set();
  for (const r of rows) {
    const v = r[i];
    if (!porteUneValeur(v)) continue;
    nonVides++;
    if (Number.isFinite(Number(v))) nombres++;
    vus.add(String(v));
  }
  return { nom, i, nonVides, nombres, cardinalite: vus.size, numerique: nonVides > 0 && nombres === nonVides };
}
function profilsDeColonnes(cols, rows) { return cols.map((nom, i) => profilDeColonne(nom, i, rows)); }
function premiereNonNumerique(rows, i) {
  for (const r of rows) { const v = r[i]; if (v !== null && v !== undefined && v !== '' && !Number.isFinite(Number(v))) return String(v).slice(0, 40); }
  return '';
}

// -- UN CHOIX IMPOSSIBLE PRODUIT UN REFUS QUI DIT POURQUOI --------------------------------------
// Trois causes, toutes DÉRIVÉES — de ce que la requête rend, et de ce que la représentation a répondu
// au sondage. Aucune ne cite un type de graphe. Le refus prend la place du GRAPHE, jamais celle des
// données : il n'est décidé dans aucun test qui jugerait aussi un vide, et il nomme la colonne, le
// compte et la valeur qui le motivent.
// -- `P11.18-p` — CE QUE LA PORTE REFUSE, SANS QU'AUCUN AXE AIT ÉTÉ CHOISI --------------------
// MESURÉ SUR BANC le 2026-08-26, les neuf représentations rendues sur `[['a','rouge'],['b','vert'],
// ['c','rouge']]`, colonnes `host, sev`, AUCUN réglage :
//   `bar`       trois barres à `width: 0%`, le texte imprimé à côté      -> FAUX
//   `line`      les trois points empilés en (320,170), axes « 0 » / « 0 » -> FAUX
//   `gauge`     « 0 / 1 » : numérateur ET dénominateur fabriqués          -> FAUX
//   `pie`       « aucune donnée » alors que trois lignes existent         -> FAUX (refus rendu en absence)
//   `donut`     idem `pie`, même fonction                                 -> FAUX
//   `heatmap`   la grille et ses en-têtes, TOUTES les cellules vides      -> FAUX
//   `histogram` « aucune donnée numérique »                               -> honnête
//   `stat`      « rouge »            |  `table` les trois lignes          -> honnêtes (elles ne tracent pas)
// SIX sur neuf, pas quatre : `donut` et `heatmap` s'ajoutent à ce que la clé nommait. ET L'HONNÊTETÉ DE
// `histogram` N'EST QUE PARTIELLE — mesuré le même jour sur `[['a',3],['b','n/a'],['c',1]]`, il rend
// « n/a » en barre de hauteur ZÉRO, exactement comme les autres ; son aveu ne sort que si AUCUNE valeur
// n'est un nombre. Le mélange est le cas dangereux : la valeur fausse est noyée dans des vraies.
//
// LE CONSTAT DE LA CLÉ EST JUSTE SUR `line`, ET IL NE PARLE PAS DE L'ORDONNÉE : « une courbe écrase
// les abscisses non numériques sur un SEUL point » est une faute d'ABSCISSE. Sur le banc ci-dessus les
// deux colonnes étaient textuelles, si bien qu'une porte posée sur la seule ordonnée l'aurait fermée
// PAR ACCIDENT. Mesuré le 2026-08-26 sur `[['a',3],['b',9],['c',1]]` — ordonnée NUMÉRIQUE, abscisse
// textuelle : `line` rendait toujours ses trois points en `320,123.3 320,30 320,154.4`, TROIS mesures
// distinctes empilées sur un même instant, sous des axes marqués « 0 » et « 0 ». La porte lit donc les
// DEUX fentes, chacune par sa propre sonde.
//
// LA RÈGLE, ET ELLE N'ÉNUMÈRE AUCUN TYPE DE GRAPHE : si le sondage a répondu que cette représentation
// ramène une fente à un NOMBRE, et que la colonne servie à cette fente n'en porte pas, la
// représentation n'est pas offerte pour cette donnée. Le sondage est la MÊME source que celle du
// réglage (`P11.18-a`) : c'est la représentation qui répond, pas une table écrite ici.
//
// DEUX CAUSES, DEUX PHRASES, parce qu'elles ne disent pas la même chose et qu'une phrase doit être
// vraie mot à mot : des valeurs qui ne sont PAS des nombres (elles seraient aplaties ou empilées), et
// une colonne SANS AUCUNE valeur (le zéro affirmerait alors une lecture qui n'a pas eu lieu).
//
// CE QUE LE REFUS D'ABSCISSE COÛTE AUX PANNEAUX LIVRÉS, ET POURQUOI CE COÛT EST NUL DANS LES DEUX CAS.
// RECOMPTÉ LE 2026-08-27, PARCE QUE LA PHRASE QUI VIVAIT ICI ÉTAIT FAUSSE : elle disait « les douze
// courbes semées passent par `| timechart` », présentant DOUZE comme la totalité. `daemon/src/seeds.rs`
// en sème SEIZE (`grep -c '"line"'`). Douze passent bien par `| timechart`, dont la projection est
// compilée hors de cet arbre : de celles-là on ne peut PAS établir ici que leur premier seau est un
// nombre. LES QUATRE AUTRES sont du SQL brut — `SELECT ts AS bucket, value FROM metric WHERE name='…'
// AND ts>=__FROM__ ORDER BY ts` (CPU %, RAM %, Réseau ↓, Température) — et leur première colonne est
// LISIBLE ici : c'est `ts`, un entier d'époque. La phrase refusait d'établir un fait qui l'était.
// LE COÛT RESTE NUL, ET L'ARGUMENT NE TIENT PLUS À LA POPULATION. Pour les quatre lues, l'abscisse EST
// un nombre : la porte ne les voit jamais. Pour les douze compilées ailleurs, la même alternative que
// toujours : si le seau est un nombre — ce que tout ce module présume déjà, le zoom temporel,
// l'infobulle et le drill ne s'armant qu'entre 1e9 et 2e10 — la porte ne les voit pas non plus ; si ce
// n'en est pas un, ces courbes empilent DÉJÀ tous leurs points sur une abscisse unique, et les refuser
// est la seule issue juste. Le refus ne se déclenche donc jamais que là où le graphe était déjà faux.
// LA BORNE DE CE RECOMPTE, écrite plutôt que tue : il porte sur les panneaux SEMÉS par ce dépôt, lus
// dans `daemon/src/seeds.rs` à cette date. Il ne dit rien d'un panneau écrit par un exploitant.
//
// CE QUE LES DEUX PORTES NE REFUSENT PAS, écrit plutôt que tu. Cette liste porte sur la porte de DONNÉE
// (juste en dessous) ET sur celle de RENDU (`refusDUneFigureMuette`), qui refuse une représentation
// traçante n'ayant posé AUCUNE marque sur des lignes servies :
//  · un résultat SANS LIGNE — l'absence est alors un FAIT, et la porte n'a rien à coercer. Ce que
//    chacune en fait a été RECOMPTÉ le 2026-08-27, parce que la phrase qui vivait ici (« chaque
//    représentation la rend déjà pour son compte ; la seule qui MENTAIT était `gauge` ») était plus
//    large que sa mesure. Sur zéro ligne, les NEUF se répartissent en trois : `gauge`, `pie`, `donut`
//    et `histogram` (depuis la correction dite plus bas) DISENT « aucune donnée » ; `stat` rend « - »
//    et `table` ses en-têtes sans ligne — ce sont des faits ; `bar`, `line` et `heatmap` rendent un
//    cadre VIDE qui n'affirme rien — ils ne mentent pas, mais ils ne disent rien non plus, et c'est un
//    reste NOMMÉ ici, pas fermé. `gauge` était bien la seule à FABRIQUER (« 0 / 1 », dont les deux termes
//    sont inventés), corrigée dans `gaugeEl` même, parce que c'est une valeur fabriquée et non un
//    refus. `histogram`, lui, disait « aucune donnée NUMÉRIQUE » là où AUCUNE donnée n'avait été
//    servie : il attribuait à la nature de la colonne une absence qu'il n'avait pas mesurée — corrigé
//    le 2026-08-27 dans `histogramEl` même, par la phrase du fait. LA LANGUE DE CES PHRASES A ÉTÉ MISE
//    EN DOUTE, ET LA MESURE A RÉFUTÉ LE DOUTE (2026-08-27) : `pie` et `donut` écrivent « aucune donnée »
//    en dur là où `gauge` et `histogram` choisissent par `LANG`, mais les DEUX chemins servent l'anglais
//    — la chaîne en dur est une clé du lexique, et `i18nWalk` rend « no data » sur le nœud de `pieEl`
//    comme sur celui de `gaugeEl` (mesuré en appliquant le parcours au nœud rendu sous `LANG='en'`).
//    Lire ces figures HORS du parcours de traduction fait voir un français qui n'atteint aucun lecteur.
//    Ce que la mesure laisse ouvert n'est donc pas la langue mais la DEUX-VOIES : deux mécanismes de
//    traduction pour la même famille de phrases, dont un seul est visible dans le module ;
//  · l'échelle que `gauge` lit en colonne 0 — la sonde d'abscisse ne mute que le rang du MILIEU, donc
//    elle ne confond pas « placer une ligne » avec « lire un maximum », et `gauge` n'est pas refusée
//    sur un résultat `[libellé, compte]`, qui est son entrée la plus naturelle ;
//  · le PLAFOND DE CARDINALITÉ de l'abscisse (`refusDeReglage`) : il juge la LISIBILITÉ, pas la
//    VÉRITÉ. Une abscisse à mille valeurs rend un graphe illisible, pas faux, et l'imposer par défaut
//    retirerait des panneaux qui se lisent aujourd'hui. Il reste attaché au CHOIX de l'exploitant ;
//  · une 2e dimension non numérique — aucune représentation ne la coerce : `heatmap`, la seule qui la
//    lise, en fait une clé de colonne, ce que le sondage rend par `fentes[1]` et non par une fente
//    coercée ;
//  · une figure qui dessine QUELQUE CHOSE mais pas TOUT. La porte de rendu ne compte pas les marques,
//    elle constate leur ABSENCE : un camembert dont le total est positif mais dont une ligne servie est
//    négative dessine, et cette ligne-là disparaît. Refuser serait retirer un graphe juste ; se taire
//    serait présenter un résultat amputé comme complet. La figure le DIT donc elle-même, en comptant ce
//    qu'elle a laissé de côté. LA DOCTRINE A ÉTÉ POSÉE SUR UNE SEULE FIGURE, ET C'ÉTAIT LE RESTE NOMMÉ
//    ICI ; il est fermé le 2026-08-27, par le MÊME écrivain (`noeudNonMontre`) sur les QUATRE endroits
//    mesurés où des lignes servies n'arrivent pas au rendu : `pieEl` (les écartées, réparties par CAUSE
//    LUE — nulle ou négative, absente, illisible — au lieu d'être toutes dites nulles), `heatmapEl` (la
//    coupe à 60 lignes et 40 colonnes, et les lignes dont une AUTRE écrase la cellule), `gaugeEl` et
//    `statEl` (toutes les lignes après la première). CE QUE CE GESTE N'EST PAS : un refus. La figure
//    reste rendue, parce qu'elle est juste sur ce qu'elle montre ; ce qui manquait était le compte.
// LES DEUX FENTES QU'UNE REPRÉSENTATION PEUT RAMENER À UN NOMBRE. Le RANG vient de la règle
// positionnelle mesurée par `P11.18-a` (première colonne en abscisse, dernière en ordonnée) ; le
// VERDICT vient du sondage, donc de la représentation elle-même ; seule la CONSÉQUENCE est écrite ici,
// parce qu'elle diffère : une ordonnée coercée aplatit les valeurs, une abscisse coercée empile les
// lignes. Une troisième fente coercée, demain, est une entrée de plus et pas une ligne de logique.
// Le fait se LIT par une fonction et non par un nom en littéral : un nom de propriété écrit en chaîne
// entre dans le regard de la garde de lexique comme un texte affichable, ce qu'il n'est pas.
// LE RANG D'UNE FENTE EST LU DANS LA TABLE DU RÉGLAGE (`FENTES_DE_REGLAGE`, plus bas), et nulle part
// ailleurs : la règle positionnelle n'a qu'UN écrivain, si bien qu'une fente déplacée là-bas se déplace
// ici sans qu'on y pense. L'écrire deux fois, c'est se donner deux règles qui finiront par diverger.
const rangDeFente = (cle, n) => (FENTES_DE_REGLAGE.find(f => f.cle === cle) || { position: () => -1 }).position(n);
const FENTES_COERCEES = [
  {
    coerce: s => s.ordonneeNumerique, rang: cols => rangDeFente('y', cols.length),
    role: { fr: 'l’ordonnée', en: 'the Y axis' },
    faux: { fr: 'Cette représentation les ramènerait toutes à ZÉRO', en: 'This representation would flatten them all to ZERO' },
  },
  {
    coerce: s => s.abscisseNumerique, rang: cols => rangDeFente('x', cols.length),
    role: { fr: 'l’abscisse', en: 'the X axis' },
    faux: { fr: 'Cette représentation les placerait toutes AU MÊME POINT', en: 'This representation would stack them all ON ONE POINT' },
  },
];
function refusDeRepresentation(mode, cols, rows) {
  if (!rows.length || !cols.length) return null;             // rien à coercer : l'absence est un fait
  const s = sondage(mode);
  for (const fente of FENTES_COERCEES) {
    if (!fente.coerce(s)) continue;                          // elle n'exprime pas cette fente en nombre
    const i = fente.rang(cols);
    const p = profilDeColonne(cols[i], i, rows);
    if (p.numerique) continue;
    if (p.nonVides === 0) return {
      fr: fente.role.fr + ' « ' + p.nom + ' » n’a AUCUNE valeur sur les ' + rows.length + ' ligne(s) servies. ' + fente.faux.fr + ', ce qui affirmerait une lecture qui n’a pas eu lieu.',
      en: fente.role.en + ' “' + p.nom + '” carries NO value at all across the ' + rows.length + ' served row(s). ' + fente.faux.en + ', asserting a reading that never happened.',
    };
    return {
      fr: fente.role.fr + ' « ' + p.nom + ' » n’est pas un nombre — ' + (p.nonVides - p.nombres) + ' valeur(s) sur ' + p.nonVides + ' n’en sont pas, par exemple « ' + premiereNonNumerique(rows, i) + ' ». ' + fente.faux.fr + ', et le graphe serait FAUX. Règle les axes, porte un agrégat à cette place, ou choisis une représentation qui ne l’exprime pas en nombre.',
      en: fente.role.en + ' “' + p.nom + '” is not a number — ' + (p.nonVides - p.nombres) + ' of ' + p.nonVides + ' values are not, for example “' + premiereNonNumerique(rows, i) + '”. ' + fente.faux.en + ', and the chart would be FALSE. Set the axes, put an aggregate in that slot, or pick a representation that does not express it as a number.',
    };
  }
  return null;
}
// -- CE QUE LA REPRÉSENTATION N'A PAS DESSINÉ, LU SUR SON PROPRE RENDU (`P11.18-p`) ------------
// TROIS FAITS, TOUS MESURÉS, AUCUN SUPPOSÉ : des lignes ont été servies ; la représentation TRACE (le
// sondage le dit, et `stat` comme `table` en sortent d'elles-mêmes, sans être nommées) ; et sur CE
// rendu-là elle n'a posé AUCUNE marque. Les trois ensemble ne laissent qu'une lecture : la figure ne
// peut pas exprimer ces valeurs. Ce n'est pas une absence de données, et le dire ainsi serait le
// mensonge que ce module poursuit — c'est un REFUS, et il prend la place du graphe comme tous les autres.
// LA RAISON EST NOMMÉE, ET ELLE VIENT DE LA COLONNE, pas d'une phrase par type : le compte des valeurs
// strictement positives, et la distinction entre « toutes nulles » et « des valeurs négatives » — un
// total nul n'a rien à répartir, et une part négative n'existe pas.
function refusDUneFigureMuette(mode, cols, rows, figure) {
  if (!rows.length || !cols.length) return null;             // l'absence est un fait, pas un refus
  if (!sondage(mode).trace) return null;                     // elle ne dessine pas : rien à compter
  if (marquesDe(figure).length) return null;                 // elle a dessiné : la figure parle d'elle-même
  // LA PHRASE SUIT LA MESURE, ELLE NE LA DEVANCE PAS. CINQ états de la colonne, cinq causes — dont celle
  // qui avoue ne pas savoir : si la colonne porte des valeurs strictement positives et que la figure n'a
  // rien dessiné quand même, la cause n'est PAS dans les valeurs, et l'écrire serait fabriquer une
  // explication. Le refus reste vrai, il se contente de dire ce qu'il a vu.
  // ILS ÉTAIENT QUATRE, ET LE COMPTE ÉTAIT FAUX (mesuré le 2026-08-27). Les valeurs étaient tirées par
  // `Number(...)` avant toute question sur leur EXISTENCE : `Number(null)` et `Number('')` valant 0 et
  // étant FINIS, une ligne SANS valeur entrait dans le compte des zéros. Sur `[['a',0],['b',null]]` la
  // phrase servie disait « ses 2 valeur(s) sont toutes NULLES » là où UNE des deux ne porte rien. Le
  // cinquième état — la colonne ne porte QUE des absences — a maintenant sa phrase, les quatre autres ne
  // comptent que ce qui a été LU, et ce qui manque est compté À PART au lieu d'être fondu dans un zéro.
  const i = cols.length - 1, nom = cols[i], col = 'la colonne « ' + nom + ' »', colEn = 'column “' + nom + '”';
  const lues = rows.map(r => r[i]).filter(porteUneValeur);
  const absentes = rows.length - lues.length;
  const nombres = lues.map(Number).filter(n => Number.isFinite(n));
  const negatives = nombres.filter(n => n < 0), positives = nombres.filter(n => n > 0);
  const manque = absentes > 0 ? {
    fr: ' ' + absentes + ' des ' + rows.length + ' ligne(s) servies ne portent AUCUNE valeur dans cette colonne : elles n’entrent dans aucun des comptes ci-dessus, une absence n’étant pas un zéro.',
    en: ' ' + absentes + ' of the ' + rows.length + ' served row(s) carry NO value at all in that column: they enter none of the counts above — an absence is not a zero.',
  } : { fr: '', en: '' };
  let cause;
  if (!lues.length) cause = {
    fr: col + ' ne porte AUCUNE valeur sur les ' + rows.length + ' ligne(s) servies : rien n’y a été lu, et un total nul serait une lecture qui n’a pas eu lieu. Porte un agrégat à cette place, ou choisis une représentation qui n’exprime pas cette fente en nombre.',
    en: colEn + ' carries NO value at all across the ' + rows.length + ' served row(s): nothing was read there, and a zero total would be a reading that never happened. Put an aggregate in that slot, or pick a representation that does not express this slot as a number.',
  }; else if (positives.length) cause = {
    fr: col + ' y porte pourtant ' + positives.length + ' valeur(s) strictement positive(s) : la cause n’est donc pas dans les valeurs, et rien ici ne permet de la nommer. Choisis une autre représentation pour cette donnée.',
    en: colEn + ' does carry ' + positives.length + ' strictly positive value(s), so the cause is NOT in the values, and nothing here allows naming it. Pick another representation for this data.',
  }; else if (!nombres.length) cause = {
    fr: 'aucune des ' + lues.length + ' valeur(s) LUES de ' + col + ' n’est un nombre. Porte un agrégat à cette place, ou choisis une représentation qui n’exprime pas cette fente en nombre.',
    en: 'none of the ' + lues.length + ' value(s) READ in ' + colEn + ' is a number. Put an aggregate in that slot, or pick a representation that does not express this slot as a number.',
  }; else if (negatives.length) cause = {
    fr: col + ' n’y porte aucune valeur strictement positive — ' + negatives.length + ' sur ' + nombres.length + ' sont NÉGATIVES (par exemple « ' + negatives[0] + ' »), et une valeur négative n’est pas une part d’un tout. Porte un agrégat strictement positif à cette place, ou choisis une représentation qui dessine des valeurs plutôt que des parts.',
    en: colEn + ' carries no strictly positive value — ' + negatives.length + ' of ' + nombres.length + ' are NEGATIVE (for example “' + negatives[0] + '”), and a negative value is not a share of a whole. Put a strictly positive aggregate in that slot, or pick a representation that draws values rather than shares.',
  }; else cause = {
    fr: col + ' n’y porte aucune valeur strictement positive — ses ' + nombres.length + ' valeur(s) sont toutes NULLES, et un total nul n’a rien à répartir. Porte un agrégat strictement positif à cette place, ou choisis une représentation qui dessine des valeurs plutôt que des parts.',
    en: colEn + ' carries no strictly positive value — its ' + nombres.length + ' value(s) are all ZERO, and a zero total has nothing to split. Put a strictly positive aggregate in that slot, or pick a representation that draws values rather than shares.',
  };
  return {
    fr: 'sur les ' + rows.length + ' ligne(s) servies, cette représentation n’a dessiné AUCUNE marque — mesuré sur ce rendu même. ' + cause.fr + manque.fr + ' LES ' + rows.length + ' LIGNES, ELLES, EXISTENT : le rendre « aucune donnée » affirmerait une absence.',
    en: 'across the ' + rows.length + ' served row(s), this representation drew NO mark at all — measured on this very rendering. ' + cause.en + manque.en + ' THE ' + rows.length + ' ROWS DO EXIST: rendering this as “no data” would assert an absence.',
  };
}

// LE NŒUD DU REFUS, ÉCRIT UNE SEULE FOIS : la porte et le refus de réglage rendent le MÊME objet, donc
// un refus se lit pareil qu'il vienne du défaut ou d'un choix. Il prend la place du GRAPHE, jamais
// celle des données.
function noeudDeRefus(refus) {
  const d = document.createElement('div');
  d.className = 'rf-hint bad';
  d.textContent = (LANG === 'en' ? 'Chart refused — ' : 'Graphe refusé — ') + (LANG === 'en' ? refus.en : refus.fr);
  return d;
}

function refusDeReglage(mode, cols, rows, reglage) {
  const s = sondage(mode), profils = profilsDeColonnes(cols, rows);
  const parNom = nom => profils.find(p => p.nom === nom) || null;
  for (const nom of [reglage.x, reglage.s, reglage.y]) {
    if (nom && !parNom(nom)) return {
      fr: 'colonne « ' + nom + ' » absente du résultat, qui ne rend plus que ' + cols.join(', ') + '. Choisis une autre colonne.',
      en: 'column “' + nom + '” is not in the result, which now returns only ' + cols.join(', ') + '. Pick another column.',
    };
  }
  // CE QUE LE RÉGLAGE NE PEUT PAS HONORER SE DIT ICI, avant tout jugement sur les VALEURS : deux fentes
  // sur la même colonne, ou une fente médiane sur un résultat sans milieu. Avant le 2026-08-27, ces deux
  // cas rendaient EXACTEMENT l'ordre sans réglage — le choix disparaissait sans un mot.
  const impossible = refusDeFentesImpossibles(mode, cols, reglage);
  if (impossible) return impossible;
  const y = reglage.y ? parNom(reglage.y) : null;
  if (y && s.ordonneeNumerique && !y.numerique) return {
    fr: 'ordonnée « ' + y.nom + ' » non numérique — ' + (y.nonVides - y.nombres) + ' valeur(s) sur ' + y.nonVides + ' n’en sont pas, par exemple « ' + premiereNonNumerique(rows, y.i) + ' ». Cette représentation les ramènerait toutes à zéro et tracerait un graphe FAUX.',
    en: 'Y axis “' + y.nom + '” is not numeric — ' + (y.nonVides - y.nombres) + ' of ' + y.nonVides + ' values are not numbers, for example “' + premiereNonNumerique(rows, y.i) + '”. This representation would coerce them all to zero and draw a FALSE chart.',
  };
  const x = reglage.x ? parNom(reglage.x) : null;
  if (x && s.trace && x.cardinalite > PLAFOND_CARDINALITE_ABSCISSE) return {
    fr: 'abscisse « ' + x.nom + ' » à ' + x.cardinalite + ' valeurs distinctes, au-dessus du plafond de ' + PLAFOND_CARDINALITE_ABSCISSE + ' : les marques se confondraient. Agrège cette colonne, ou porte-la en ordonnée.',
    en: 'X axis “' + x.nom + '” has ' + x.cardinalite + ' distinct values, above the ceiling of ' + PLAFOND_CARDINALITE_ABSCISSE + ': the marks would merge. Aggregate that column, or move it to the Y axis.',
  };
  return null;
}

// -- LE RÉGLAGE SE POSE AU-DESSUS DE LA RÈGLE : IL REMET LES COLONNES DANS L'ORDRE VOULU --------
// LES TROIS FENTES, ET UN SEUL NOMBRE POUR CHACUNE. Ce nombre est À LA FOIS la POSITION que la fente
// occupe dans ce qui est remis au graphe et le RANG que la règle positionnelle lui donne quand personne
// ne l'a réglée (`P11.18-a` : première colonne en abscisse, deuxième en 2e dimension, dernière en
// ordonnée). Les deux coïncident, et les écrire deux fois les ferait diverger — `FENTES_COERCEES`, plus
// haut, LIT cette table par `rangDeFente` au lieu de réécrire les mêmes rangs. `sonde` est le rang que la fente occupe dans le jeu à
// trois colonnes du sondage : c'est par LUI qu'on demande à la représentation si elle la lit, plutôt que
// de l'écrire par type. `ancre` dit à quoi la position est attachée — un BORD du résultat, ou son MILIEU
// — et de quel côté chercher une colonne libre quand le rang préféré est déjà pris par un CHOIX.
const FENTES_DE_REGLAGE = [
  { cle: 'x', sonde: 0, ancre: 'debut', position: () => 0,
    libelle: { fr: 'Abscisse ', en: 'X axis ' },
    infobulle: { fr: 'Colonne remise au graphe en première position', en: 'Column handed to the chart in first position' } },
  { cle: 's', sonde: 1, ancre: 'milieu', position: () => 1,
    libelle: { fr: '2e dimension ', en: '2nd dimension ' },
    infobulle: { fr: 'Colonne remise au graphe en position médiane', en: 'Column handed to the chart in middle position' } },
  { cle: 'y', sonde: 2, ancre: 'fin', position: n => n - 1,
    libelle: { fr: 'Ordonnée ', en: 'Y axis ' },
    infobulle: { fr: 'Colonne remise au graphe en dernière position', en: 'Column handed to the chart in last position' } },
];
// UNE FENTE MÉDIANE N'EXISTE QUE SI LE RÉSULTAT A UN MILIEU — un rang qui n'est ni le premier ni le
// dernier — ET si la représentation a dit lire ce rang. Les deux fentes ancrées à un BORD existent dès
// qu'une colonne est servie. Aucun type de graphe n'est nommé : le verdict vient du sondage.
function fentePlacable(f, cols) { return f.ancre !== 'milieu' ? cols.length > 0 : (f.position(cols.length) > 0 && f.position(cols.length) < cols.length - 1); }
function fenteOfferte(f, son, cols, reglage) { return !!reglage[f.cle] || (fentePlacable(f, cols) && !!son.fentes[f.sonde]); }
// CE QU'UN RÉGLAGE NE PEUT PAS FAIRE, ET QUI SE DIT AU LIEU DE S'ÉVANOUIR. Deux impossibilités, toutes
// deux DÉRIVÉES du résultat servi : deux fentes réglées sur la MÊME colonne — une colonne n'occupe
// qu'une position — et une fente MÉDIANE réglée là où il n'y a pas de milieu (moins de trois colonnes,
// la position médiane y ÉTANT la dernière). Elles rendent le même objet de refus que tout le reste, donc
// elles prennent la place du GRAPHE et la barre reste au-dessus pour les défaire.
function refusDeFentesImpossibles(mode, cols, reglage) {
  const son = sondage(mode);
  // Seules comptent les fentes que la représentation LIT : un choix posé sur une fente qu'elle ignore
  // ne peut RIEN empêcher, et le refuser serait crier au loup (`P11.18-q`).
  const posees = FENTES_DE_REGLAGE.filter(f => reglage[f.cle] && son.fentes[f.sonde]);
  for (const f of posees) {
    const autre = posees.find(g => g !== f && reglage[g.cle] === reglage[f.cle]);
    if (autre) return {
      fr: 'la colonne « ' + reglage[f.cle] + ' » est réglée à la fois sur « ' + f.libelle.fr.trim() + ' » et sur « ' + autre.libelle.fr.trim() + ' », et une colonne n’occupe qu’UNE position dans ce qui est remis au graphe. Remets l’une des deux fentes sur « (par défaut) », ou porte-la sur une autre colonne.',
      en: 'column “' + reglage[f.cle] + '” is set on both “' + f.libelle.en.trim() + '” and “' + autre.libelle.en.trim() + '”, and one column occupies only ONE position in what is handed to the chart. Put one of the two slots back on “(default)”, or move it to another column.',
    };
    if (f.ancre === 'milieu' && !fentePlacable(f, cols)) return {
      fr: '« ' + f.libelle.fr.trim() +' » est une position MÉDIANE, et un résultat de ' + cols.length + ' colonne(s) n’a pas de milieu : le rang médian y est le dernier. Ce réglage ne peut pas être honoré tel quel. Remets cette fente sur « (par défaut) », ou porte une colonne de plus au résultat.',
      en: '“' + f.libelle.en.trim() + '” is a MIDDLE position, and a ' + cols.length + '-column result has no middle: the middle rank is the last one. This setting cannot be honoured as it stands. Put that slot back on “(default)”, or return one more column.',
    };
  }
  return null;
}
// LE CHOIX PASSE AVANT LE DÉFAUT, ET C'ÉTAIT TOUT CE QUI MANQUAIT (mesuré le 2026-08-27). Cette fonction
// RÉSERVAIT les rangs de tête avant sa boucle, si bien que la pose finale de l'ordonnée ne faisait RIEN
// quand sa colonne était déjà placée : l'ordre retombait sur l'IDENTITÉ. Sur cinq colonnes servies, DEUX
// choix d'ordonnée sur cinq étaient inertes (`y=host`, `y=user`) ; sur trois colonnes, DEUX sur TROIS ;
// la 2e dimension portait le même défaut (`s=host` rendait l'ordre servi). Le sélecteur continuait
// pourtant d'afficher le choix, l'infobulle affirmait « colonne remise au graphe en dernière position »,
// et l'aveu de réglage privé se taisait puisque rien n'avait bougé — l'exploitant croyait avoir agi.
// LE REMÈDE FERME LE CHEMIN : un CHOIX réserve sa colonne AVANT qu'un seul défaut ne soit lu, et un
// défaut dont le rang préféré est pris se replie sur la colonne LIBRE la plus proche de son ancre. Quand
// aucun choix n'est posé, aucun rang n'est pris et chaque fente reçoit exactement le rang que la règle
// positionnelle lui donnait : le chemin par défaut est byte-identique, et un témoin le tient.
function fentesResolues(mode, cols, reglage) {
  const son = sondage(mode), n = cols.length;
  const choisi = new Map();
  for (const f of FENTES_DE_REGLAGE) if (reglage[f.cle]) choisi.set(f.cle, cols.indexOf(reglage[f.cle]));
  // UN CHOIX NE RÉSERVE SA COLONNE QUE SUR UNE FENTE QUE LA REPRÉSENTATION LIT. Mesuré le 2026-08-27 :
  // réserver sans cette condition faisait qu'un axe posé sur une fente IGNORÉE (l'abscisse de `stat`)
  // repoussait le défaut de la fente LUE sur une autre colonne — le chiffre affiché changeait à cause
  // d'un réglage sans effet. Un réglage qui ne déplace rien de ce que la figure lit ne doit rien
  // déplacer du tout : c'est ce que le témoin 46i tient, et c'est la borne de cette réservation.
  const pris = new Set(FENTES_DE_REGLAGE.filter(f => choisi.has(f.cle) && son.fentes[f.sonde]).map(f => choisi.get(f.cle)));
  const resolu = new Map();
  for (const f of FENTES_DE_REGLAGE) {
    if (choisi.has(f.cle)) { resolu.set(f.cle, choisi.get(f.cle)); continue; }
    if (!fentePlacable(f, cols) || (f.ancre === 'milieu' && !son.fentes[f.sonde])) continue;
    const p = f.position(n);
    if (p >= 0 && p < n && !pris.has(p)) { pris.add(p); resolu.set(f.cle, p); continue; }
    const libres = cols.map((_, i) => i).filter(i => !pris.has(i));
    const repli = libres.length ? (f.ancre === 'fin' ? libres[libres.length - 1] : libres[0]) : p;
    pris.add(repli); resolu.set(f.cle, repli);
  }
  return resolu;
}
// UN RÉGLAGE RANGE, IL NE RETIRE JAMAIS — mesuré le 2026-08-27. Cette fonction construisait
// `[abscisse, (2e dimension), ordonnée]`, soit AU PLUS TROIS rangs, quel que soit le nombre de colonnes
// que la représentation rend. Sur `table`, qui les rend TOUTES, un réglage posé sur cinq colonnes servies
// faisait rendre QUATRE en-têtes là où le même appel sans réglage en rendait SIX : deux colonnes servies
// par le démon disparaissaient, l'en-tête et la numérotation des lignes présentaient le reste comme le
// résultat complet, et rien ne le disait. Le sondage sait désormais si la représentation lit AU-DELÀ des
// trois fentes ; pour celle-là, l'ordre est une PERMUTATION COMPLÈTE : les fentes RÉSOLUES prennent leur
// position, et les colonnes qu'aucune fente n'occupe remplissent les positions restantes DANS LEUR ORDRE
// SERVI. Sans réglage, cette permutation est l'IDENTITÉ.
function ordreDeFentes(mode, cols, reglage) {
  if (!cols.length) return [];
  const resolu = fentesResolues(mode, cols, reglage);
  const ordre = FENTES_DE_REGLAGE.filter(f => resolu.has(f.cle)).map(f => resolu.get(f.cle));
  if (!sondage(mode).litAuDelaDesFentes) return ordre;
  // La permutation ne place que les fentes que la représentation LIT, et jamais deux fois la même
  // colonne : ce qui reste est exactement le complément, donc le remplissage ne peut pas manquer de
  // colonne — la sortie est une permutation, pas une liste qui pourrait perdre un rang.
  const son = sondage(mode), cible = new Map();
  for (const f of FENTES_DE_REGLAGE) {
    if (!resolu.has(f.cle) || !son.fentes[f.sonde]) continue;
    const p = f.position(cols.length), i = resolu.get(f.cle);
    if (p >= 0 && p < cols.length && !cible.has(p) && ![...cible.values()].includes(i)) cible.set(p, i);
  }
  const places = new Set(cible.values());
  const reste = cols.map((_, i) => i).filter(i => !places.has(i));
  return cols.map((_, p) => (cible.has(p) ? cible.get(p) : reste.shift()));
}
function projeter(mode, cols, rows, reglage) {
  const ordre = ordreDeFentes(mode, cols, reglage);
  return { cols: ordre.map(i => cols[i]), rows: rows.map(r => ordre.map(i => r[i])) };
}

// -- LA SURFACE DE RÉGLAGE ---------------------------------------------------------------------
// Elle vit LÀ OÙ LE GRAPHE EST, jamais derrière une entrée qu'il faut deviner : `P11.17-b` a mesuré
// ce que coûte un accès qu'on ne prend pas. Les fentes offertes sont celles que la représentation a
// dit lire au sondage — une représentation qui ne lit pas de 2e dimension n'en propose pas, plutôt
// que d'offrir un contrôle sans effet ; et les colonnes offertes sont celles que la requête rend.
function selecteurDeFente(libelle, infobulle, colonnes, choix, onChoix) {
  const l = document.createElement('label');
  const s = document.createElement('select');
  s.title = infobulle;
  const zero = document.createElement('option');
  zero.value = ''; zero.textContent = LANG === 'en' ? '(default)' : '(par défaut)';
  s.appendChild(zero);
  colonnes.forEach(p => { const o = document.createElement('option'); o.value = p.nom; o.textContent = p.nom; s.appendChild(o); });
  // UNE COLONNE CHOISIE QUE LE RÉSULTAT NE REND PLUS RESTE OFFERTE, marquée absente. Sans elle, le
  // sélecteur affichait « (par défaut) » alors que le réglage était ACTIF — il disait le contraire de
  // ce qui s'appliquait — et re-choisir « (par défaut) » ne déclenchait aucun changement : le réglage
  // impossible n'avait plus de sortie, alors même que le refus au-dessus invitait à en changer.
  if (choix && !colonnes.some(p => p.nom === choix)) {
    const o = document.createElement('option');
    o.value = choix; o.textContent = choix + (LANG === 'en' ? ' (missing from the result)' : ' (absente du résultat)');
    s.appendChild(o);
  }
  s.value = choix || '';
  s.onchange = () => onChoix(s.value || '');
  l.append(libelle, s);
  return l;
}
// LA BARRE EST DÉRIVÉE DE LA MÊME TABLE QUE L'ORDRE, libellés et infobulles compris : le refus qui dit
// « la colonne est réglée à la fois sur « Ordonnée » et sur « Abscisse » » nomme donc EXACTEMENT le
// contrôle que l'exploitant voit, et une fente posée demain apporte son libellé sans qu'on l'écrive ici.
// CE QU'UNE FENTE OFFERTE PROMET, ET RIEN DE PLUS : elle est offerte si la représentation a dit lire son
// rang ET si sa position existe dans ce résultat. Une fente RÉGLÉE reste offerte quoi qu'il arrive — une
// fente qu'on ne peut plus atteindre est un réglage qu'on ne peut plus défaire — et si elle ne peut pas
// être honorée, c'est un REFUS qui le dit, à la place du graphe. Avant le 2026-08-27, une 2e dimension
// était offerte sur un résultat de deux colonnes, où la position médiane EST la dernière : le choix
// s'évanouissait en silence. MESURÉ ce jour-là, les neuf représentations répondent toutes « je lis le
// dernier rang », si bien que la fente d'ordonnée reste offerte partout sans être écrite comme une
// exception — c'est le sondage qui le dit, et non une ligne d'ici.
function barreDeReglage(mode, cols, rows, reglage, onChoix) {
  const son = sondage(mode), profils = profilsDeColonnes(cols, rows);
  const barre = document.createElement('div');
  barre.className = 'rf-row';
  for (const f of FENTES_DE_REGLAGE) {
    if (!fenteOfferte(f, son, cols, reglage)) continue;
    barre.appendChild(selecteurDeFente(
      LANG === 'en' ? f.libelle.en : f.libelle.fr,
      LANG === 'en' ? f.infobulle.en : f.infobulle.fr,
      profils, reglage[f.cle], v => onChoix(Object.assign({}, reglage, { [f.cle]: v }))));
  }
  return barre;
}

// -- CE QUE CE RÉGLAGE NE PARTAGE PAS, DIT LÀ OÙ IL EST LU (`P11.18-q`) ------------------------
// LA QUESTION QUE LA CLÉ POSAIT — le réglage appartient-il au PANNEAU ou à la PERSONNE — est
// TRANCHÉE ICI, ET DU CÔTÉ DE LA PERSONNE. Ce n'est pas une préférence : le panneau n'a AUCUNE
// fente où loger un axe (mesuré le 2026-08-25 et revérifié le 2026-08-26 sur `panel_update` : le
// corps accepté est titre, requête, is_soql, fenêtre, visibilité, requête privée, largeur de grille
// `cols` — bornée à 1..4, ce n'est pas une liste de colonnes —, hauteur, drill, position et
// référence de bibliothèque). Le faire porter par le panneau demande une capacité NOUVELLE du démon,
// pas une ligne de ce module. Le côté choisi étant celui de la personne, ce que la clé exige alors
// est écrit ici : LA VUE DIT QUE CE QU'ELLE MONTRE EST UN RÉGLAGE PRIVÉ.
//
// L'AVEU EST DÉRIVÉ DE LA DIVERGENCE, PAS DE L'EXISTENCE D'UN RÉGLAGE. Un réglage qui redonne
// l'ordre par défaut (choisir explicitement la première colonne en abscisse) ne cache RIEN à
// personne : la vue rend alors EXACTEMENT ce que le panneau sert — empreinte identique, mesurée — et
// l'annoncer serait un bruit qui apprendrait à ne plus lire l'avis. La condition est donc « ce que la
// représentation LIT diffère de ce qu'elle lirait sans réglage » — plus le refus, qui remplace le
// graphe par un texte que les autres ne voient pas non plus.
// CETTE JUSTIFICATION A ÉTÉ FAUSSE, ET LA MESURE L'A MONTRÉE FAUSSE (2026-08-27). Elle valait de ce que
// la vue LIT, jamais de ce qu'elle REND, et les deux divergeaient sur `table` — la représentation qui
// rend TOUTES les colonnes. Sur cinq colonnes servies, le réglage « x=host, y=n », c'est-à-dire
// exactement « l'ordre par défaut redonné », faisait rendre QUATRE en-têtes là où le même appel sans
// réglage en rendait SIX : deux colonnes servies par le démon disparaissaient, l'en-tête et la
// numérotation des lignes présentaient le reste comme le résultat complet, et cette comparaison
// n'y voyait aucune divergence puisqu'elle ne compare QUE trois positions. Le lecteur ne pouvait pas
// savoir ce qui avait été servi, donc pas savoir que deux colonnes manquaient : « ne cache rien à
// personne » était l'inverse de ce que le code faisait. LA CAUSE ÉTAIT EN AMONT DE L'AVEU, dans
// `ordreDeFentes`, qui projetait sur au plus TROIS rangs quel que soit le nombre de colonnes rendues.
// Elle y est corrigée : sur une telle représentation le réglage RANGE et ne retire plus rien, l'aveu
// n'a donc plus de colonne perdue à annoncer, et la signature comparée ci-dessous suit désormais
// l'ordre ENTIER pour ces représentations-là.
// ET C'EST BIEN CE QU'ELLE LIT, PAS L'ORDRE BRUT. Comparer les ordres suffirait pour les
// représentations qui lisent tout, et mentirait pour les autres : `stat` ne lit que la DERNIÈRE fente,
// donc régler son abscisse déplace un rang que rien ne consulte — l'ordre diffère, le graphe est
// identique, et l'annoncer ferait crier au loup. La signature comparée est donc l'ordre RESTREINT aux
// fentes que le sondage a dit lues (première, médiane, dernière). Rien n'est écrit par type : une
// représentation posée demain est sondée pareil et entre dans cette comparaison sans qu'on y pense.
//
// L'AVEU NOMME CE QUE LES AUTRES VOIENT, sans quoi il ne serait qu'un avertissement : il rend les
// colonnes que le panneau, TEL QU'IL EST ENREGISTRÉ, remet au graphe. Le chemin du retour n'est pas
// un bouton de plus — c'est la fente « (par défaut) » qui existe déjà au-dessus, et l'aveu la nomme.
//
// CE QUE CET AVEU NE DIT PAS : rien de la mise en page ni du style. Et il ne PARLE PAS d'un appelant
// sans identité de panneau (`idPanneau` absent) : la clé de mémorisation est alors la signature des
// colonnes d'une surface qui n'a pas d'objet persistant, il n'existe aucun panneau enregistré dont
// on pourrait s'écarter, donc rien à déclarer — ce n'est pas un silence, c'est une absence d'objet.
// CE QUE CETTE SIGNATURE N'A PAS BESOIN DE FAIRE, ET LA MUTATION QUI L'ÉTABLIT (2026-08-27). L'aveu
// nommait TROIS colonnes à qui en voyait cinq ; on a cru qu'il fallait signer l'ordre ENTIER pour les
// représentations qui rendent toutes leurs colonnes. Rejoué par MUTATION : cette variante ne change
// AUCUN verdict, sur aucun mode. La raison est que l'ordre entier est ENTIÈREMENT DÉTERMINÉ par les
// trois fentes (les colonnes non choisies gardent leur ordre servi), si bien que « l'ordre entier
// diffère » et « une des trois positions diffère » sont la MÊME phrase. Ce qui manquait n'était donc
// pas ici : c'était que `ordreDeFentes` RETIRE des colonnes, ce qu'il ne fait plus — l'aveu lit cet
// ordre-là et nomme désormais tout ce que le panneau sert. Une variante dont la mutation ne change
// rien n'est pas une garde : elle n'est pas écrite.
function signatureLue(mode, cols, ordre) {
  const f = sondage(mode).fentes;
  return [
    f[0] ? cols[ordre[0]] : '',
    (ordre.length >= 3 && f[1]) ? cols[ordre[1]] : '',
    f[2] ? cols[ordre[ordre.length - 1]] : '',
  ].join('\x1f');
}
function avisDeReglagePrive(colsParDefaut) {
  const d = document.createElement('div');
  d.className = 'rf-hint';
  const ordre = colsParDefaut.join(' → ');
  d.textContent = LANG === 'en'
    ? 'Private setting — these axes are stored on YOUR account, not in the panel: nobody else sees them, and a shareable snapshot does not carry them. As saved, the panel hands the chart “' + ordre + '”. Put every slot back on “(default)” to get back what the others see.'
    : 'Réglage privé — ces axes sont mémorisés sur VOTRE compte, pas dans le panneau : personne d’autre ne les voit, et l’instantané partageable ne les emporte pas. Tel qu’il est enregistré, le panneau remet au graphe « ' + ordre + ' ». Remets chaque fente sur « (par défaut) » pour retrouver ce que voient les autres.';
  return d;
}

// -- LE GRAPHE RÉGLÉ ---------------------------------------------------------------------------
// Rend une LISTE de nœuds, jamais une enveloppe : une enveloppe changerait la mise en page de tous
// les appelants. Sans réglage mémorisé, le graphe est l'appel `vizElement` D'ORIGINE, sur les colonnes
// et les lignes D'ORIGINE — aucune projection n'a lieu. Le refus, quand il y en a un, prend la place
// du graphe, et la barre reste au-dessus : sans quoi un choix impossible serait sans issue.
function noeudsDeVizReglee(mode, cols, rows, query, drill, idPanneau, redessiner) {
  const cle = cleDeReglage(idPanneau, cols);
  const reglage = reglageLu(cle) || {};
  const regle = !!(reglage.x || reglage.y || reglage.s);
  const out = [];
  // Sous DEUX colonnes il n'y a rien à choisir : le résultat n'a qu'une fente. La barre ne s'affiche pas,
  // et aucun réglage ne peut donc changer l'arité de ce qui est remis au graphe.
  // MAIS UN RÉGLAGE EN VIGUEUR AMÈNE TOUJOURS SA BARRE. Mesuré le 2026-08-26 : un réglage posé sur un
  // résultat à trois colonnes SURVIT à une requête réécrite qui n'en rend plus qu'une, et à un passage
  // vers une représentation qui ne trace pas — dans les deux cas il continuait de s'appliquer pendant
  // que le seul contrôle capable de le défaire disparaissait. Le commentaire du refus, juste en dessous,
  // affirmait pourtant que « la barre reste au-dessus, sans quoi un choix impossible serait sans issue » :
  // c'était vrai du refus, faux de ce cas-là. `P11.18-q` en dépend directement — l'aveu qu'il pose nomme
  // « (par défaut) » comme chemin de retour, et un chemin nommé doit exister.
  if (regle || (sondage(mode).trace && cols.length >= 2)) out.push(barreDeReglage(mode, cols, rows, reglage, r => { reglageEcrit(cle, r); redessiner(); }));
  if (!regle) { out.push(vizElement(mode, cols, rows, query, drill)); return out; }
  const refus = refusDeReglage(mode, cols, rows, reglage);
  // `P11.18-q` — les DEUX ordres, comparés avant de rendre quoi que ce soit : celui que ce compte
  // voit, et celui que le panneau enregistré remet au graphe pour tout le monde.
  const ordreParDefaut = ordreDeFentes(mode, cols, {});
  const divergent = !!refus
    || signatureLue(mode, cols, ordreDeFentes(mode, cols, reglage)) !== signatureLue(mode, cols, ordreParDefaut);
  if (idPanneau && divergent) out.push(avisDeReglagePrive(ordreParDefaut.map(i => cols[i])));
  if (refus) { out.push(noeudDeRefus(refus)); return out; }   // `P11.18-p` : UN seul écrivain du nœud de refus
  const p = projeter(mode, cols, rows, reglage);
  out.push(vizElement(mode, p.cols, p.rows, query, drill));
  return out;
}


// Palette catégorielle stable (dérivée des variables de thème avec repli) : indexée par position -> une
// même catégorie garde sa couleur d'un rendu à l'autre. Vendor-free (aucune dépendance).
const PIE_COLORS = ['--acc', '--sev1', '--sev2', '--sev3', '--sev4', '--ok', '--warn', '--bad'];
function catColor(i) {
  const fallback = ['#2dd4bf', '#3b82f6', '#a78bfa', '#f59e0b', '#ef4444', '#22c55e', '#eab308', '#f43f5e'];
  return CSSV(PIE_COLORS[i % PIE_COLORS.length], fallback[i % fallback.length]);
}

// UNE FIGURE QUI NE LIT QU'UNE LIGNE LE DIT, ET CE N'EST PAS UN REFUS. Mesuré le 2026-08-27 : sur CINQ
// lignes servies `[['a',10]..['e',50]]`, `stat` rendait « 10 » et `gauge` « 10 / 10 » — QUATRE lignes sur
// cinq retirées, la valeur unique présentée comme LE résultat, et aucun mot, là où `table` sur la même
// donnée rend les cinq. La porte de RENDU ne peut pas rattraper ce cas : elle constate l'ABSENCE de
// marque, et l'arc de piste comme le chiffre sont bien dessinés. C'est donc la doctrine de `pieEl` qui
// s'applique — compter ce qu'on laisse de côté et l'écrire — et elle vaut aussi pour une figure qui NE
// TRACE PAS : `stat` ne trace pas, et présentait pourtant un résultat amputé avec les attributs du
// résultat complet. La phrase ne nomme AUCUNE colonne : ce qui est retiré est une LIGNE, pas une valeur.
function noeudUneSeuleLigne(figure, rows) {
  if (rows.length <= 1) return figure;
  const wrap = document.createElement('div');
  wrap.append(figure, noeudNonMontre([LANG === 'en'
    ? (rows.length - 1) + ' of the ' + rows.length + ' served row(s) are not read: this representation renders only the FIRST one'
    : (rows.length - 1) + ' des ' + rows.length + ' ligne(s) servies ne sont pas lues : cette représentation ne rend que la PREMIÈRE']));
  return wrap;
}

// GAUGE — une seule valeur (comme stat) rendue en arc (jauge 270°). Max déduit : name='cpu_pct'/%→100,
// sinon la valeur elle-même sert d'échelle (pleine). Clic -> drill (comme stat).
function gaugeEl(cols, rows, query, drill) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const key = unitKeyFor(cols, query);
  // `P11.18-p` — ZÉRO LIGNE N'EST PAS LA VALEUR ZÉRO. Mesuré le 2026-08-26 : sur un résultat SANS
  // AUCUNE ligne, cette jauge affichait « 0 / 1 » — un rapport dont les DEUX termes sont fabriqués,
  // alors que rien n'a été mesuré. Toutes les autres représentations rendent déjà cette absence pour
  // leur compte (`stat` rend « - », `pie` et `histogram` la disent) ; celle-ci l'affirmait à l'envers.
  // Ce n'est pas un REFUS — la donnée n'a rien d'impossible — donc cela se règle ici et non à la porte.
  if (!rows.length) return muted(LANG === 'en' ? 'no data' : 'aucune donnée');
  const raw = Number(rows[0][rows[0].length - 1]);
  const v = Number.isFinite(raw) ? raw : 0;
  // échelle : % -> 100 ; sinon max explicite (rows fournit [val,max]) sinon arrondi « joli » au-dessus de v.
  const pct = key && UNITS[key] === '%';
  let max = pct ? 100 : (rows.length && rows[0].length > 1 ? Number(rows[0][0]) : 0);
  if (!max || max <= 0) { const m = Math.max(1, v); const p = Math.pow(10, Math.floor(Math.log10(m))); max = Math.ceil(m / p) * p; }
  const frac = Math.max(0, Math.min(1, v / max));
  const W = 220, H = 150, cx = W / 2, cy = H - 24, r = 84, START = Math.PI * 0.75, SWEEP = Math.PI * 1.5;
  const pt = a => [cx + r * Math.cos(a), cy - r * Math.sin(a) * -1]; // y-down : sin inversé
  const arc = (a0, a1, color, w) => {
    const [x0, y0] = pt(a0), [x1, y1] = pt(a1); const large = (a1 - a0) > Math.PI ? 1 : 0;
    const p = mk('path'); p.setAttribute('d', `M${x0},${y0} A${r},${r} 0 ${large} 1 ${x1},${y1}`);
    p.setAttribute('fill', 'none'); p.setAttribute('stroke', color); p.setAttribute('stroke-width', w); p.setAttribute('stroke-linecap', 'round'); return p;
  };
  const svg = mk('svg'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('class', 'gaugechart');
  // angles : START à gauche-haut, on tourne dans le sens horaire de SWEEP.
  const a0 = START, aEnd = START - SWEEP, aVal = START - SWEEP * frac;
  svg.appendChild(arc(a0, aEnd, CSSV('--bd', '#16202e'), 12));       // piste
  if (frac > 0) svg.appendChild(arc(a0, aVal, CSSV('--acc', '#2dd4bf'), 12)); // remplissage
  const txt = (y, s, cls, size) => { const e = mk('text'); e.setAttribute('x', cx); e.setAttribute('y', y); e.setAttribute('text-anchor', 'middle'); e.setAttribute('fill', CSSV(cls, '#e6eef6')); e.setAttribute('font-size', size); e.textContent = s; svg.appendChild(e); };
  txt(cy - 6, fmtVal(key, v), '--fg', 26); txt(cy + 16, '/ ' + fmtVal(key, max), '--mut', 12);
  if (query || drill) { svg.style.cursor = 'pointer'; svg.onclick = () => statDrill(query, drill); }
  return noeudUneSeuleLigne(svg, rows);
}

// PIE / DONUT — catégorie + valeur ([label, count]). Secteurs SVG proportionnels + légende. Clic secteur -> drill.
// CE QUE CETTE FIGURE NE MONTRE PAS, ELLE LE DIT (`P11.18-p`). Deux pertes, toutes deux COMPTÉES sur ce
// rendu et jamais énumérées : les lignes servies qu'aucun secteur ne porte (`.filter(d => d.v > 0)` juste
// en dessous), et les catégories dessinées que la légende ne liste pas. Se taire sur l'une ou l'autre
// présenterait un résultat AMPUTÉ avec les attributs du résultat complet. Quand rien n'est perdu, rien
// n'est ajouté : c'est ce qui garde la non-régression byte-identique des panneaux qui se lisent aujourd'hui.
// LA PERTE EST NOMMÉE PAR SA CAUSE, ET LA CAUSE EST LUE (mesuré le 2026-08-27). Cette phrase disait « leur
// valeur est nulle ou négative » de TOUTE ligne écartée, alors que `Math.max(0, Number(v) || 0)` fabrique
// un zéro à partir d'une absence (`null`, chaîne vide) comme d'une valeur illisible : la figure NOMMAIT
// une lecture qu'elle n'avait pas faite, dans le geste même dont l'objet est de dire ce qu'elle ne montre
// pas. Les écartées sont donc réparties en TROIS causes distinctes, comptées séparément, et seule celle
// qui a au moins une ligne est écrite. LA BORNE DE CETTE RÉPARTITION : par `vizElement`, la cause
// « illisible » est INATTEIGNABLE — la porte de donnée refuse une ordonnée non numérique avant d'arriver
// ici ; elle ne se rencontre que par `vizSansPorte`, et c'est là qu'un témoin l'exerce.
// UN SEUL ÉCRIVAIN DU NŒUD « NON MONTRÉ », comme il n'y a qu'un seul écrivain du nœud de REFUS. Les deux
// ne disent pas la même chose et ne prennent pas la même place : un REFUS remplace le graphe, un AVEU DE
// PERTE l'accompagne. Une figure qui dessine QUELQUE CHOSE mais pas TOUT compte ce qu'elle a laissé de
// côté et l'écrit ici ; quand elle ne perd rien, elle n'ajoute rien, et le balisage d'aujourd'hui ne bouge pas.
function noeudNonMontre(bouts) {
  const dit = document.createElement('div'); dit.className = 'rf-hint';
  dit.textContent = (LANG === 'en' ? 'Not shown — ' : 'Non montré — ') + bouts.join(' ; ') + '.';
  return dit;
}
const PLAFOND_LEGENDE = 12;   // au-delà, la légende dépasse la figure et cesse d'être lisible
function pieEl(cols, rows, query, drill, donut) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const vi = cols.length - 1;
  const data = rows.map(r => ({ label: r[0] == null ? '-' : String(r[0]), v: Math.max(0, Number(r[vi]) || 0) })).filter(d => d.v > 0);
  const total = data.reduce((s, d) => s + d.v, 0);
  const wrap = document.createElement('div'); wrap.className = 'piewrap';
  if (!total) { wrap.appendChild(muted('aucune donnée')); return wrap; }
  const W = 180, cx = W / 2, cy = W / 2, r = 78, rin = donut ? 44 : 0;
  const svg = mk('svg'); svg.setAttribute('viewBox', `0 0 ${W} ${W}`); svg.setAttribute('class', 'piechart');
  let a0 = -Math.PI / 2;
  data.forEach((d, i) => {
    const frac = d.v / total, a1 = a0 + frac * Math.PI * 2;
    const large = (a1 - a0) > Math.PI ? 1 : 0;
    const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0), x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
    const seg = mk('path'); const color = catColor(i);
    if (rin > 0) {
      const xi0 = cx + rin * Math.cos(a1), yi0 = cy + rin * Math.sin(a1), xi1 = cx + rin * Math.cos(a0), yi1 = cy + rin * Math.sin(a0);
      seg.setAttribute('d', `M${x0},${y0} A${r},${r} 0 ${large} 1 ${x1},${y1} L${xi0},${yi0} A${rin},${rin} 0 ${large} 0 ${xi1},${yi1} Z`);
    } else {
      seg.setAttribute('d', `M${cx},${cy} L${x0},${y0} A${r},${r} 0 ${large} 1 ${x1},${y1} Z`);
    }
    seg.setAttribute('fill', color); seg.setAttribute('stroke', CSSV('--card', '#0c1422')); seg.setAttribute('stroke-width', '1');
    const tipTxt = `${d.label} : ${d.v} (${(frac * 100).toFixed(1)}%)`;
    seg.addEventListener('mousemove', e => tipShow(tipTxt, e)); seg.addEventListener('mouseleave', tipHide);
    if (drill) { seg.style.cursor = 'pointer'; seg.onclick = () => customDrill(drill, { value: d.label }); }
    else if (!DIMENSIONLESS.has(cols[0])) { seg.style.cursor = 'pointer'; seg.onclick = () => drilldown(cols[0], d.label); }
    svg.appendChild(seg); a0 = a1;
  });
  const legend = document.createElement('div'); legend.className = 'pielegend';
  data.slice(0, PLAFOND_LEGENDE).forEach((d, i) => {
    const row = document.createElement('div'); row.className = 'pielg';
    const sw = document.createElement('span'); sw.className = 'pieswatch'; sw.style.background = catColor(i);
    const lb = document.createElement('span'); lb.className = 'pielabel'; lb.textContent = d.label;
    const vc = document.createElement('span'); vc.className = 'pieval'; vc.textContent = d.v;
    row.append(sw, lb, vc); legend.appendChild(row);
  });
  wrap.append(svg, legend);
  const ecartees = rows.filter(r => !(Math.max(0, Number(r[vi]) || 0) > 0));
  const absentes = ecartees.filter(r => !porteUneValeur(r[vi])).length;
  const illisibles = ecartees.filter(r => porteUneValeur(r[vi]) && !Number.isFinite(Number(r[vi]))).length;
  const nonPositives = ecartees.length - absentes - illisibles;
  const nonListees = Math.max(0, data.length - PLAFOND_LEGENDE);
  if (ecartees.length > 0 || nonListees > 0) {
    const bouts = [];
    if (nonPositives > 0) bouts.push(LANG === 'en'
      ? nonPositives + ' of the ' + rows.length + ' served row(s) are drawn by no sector: their value is zero or negative, which is not a share of a whole'
      : nonPositives + ' des ' + rows.length + ' ligne(s) servies ne sont portées par aucun secteur : leur valeur est nulle ou négative, ce qui n’est pas une part d’un tout');
    if (absentes > 0) bouts.push(LANG === 'en'
      ? absentes + ' of the ' + rows.length + ' served row(s) carry NO value in “' + cols[vi] + '”: nothing was read there, and an absence is not a zero'
      : absentes + ' des ' + rows.length + ' ligne(s) servies ne portent AUCUNE valeur dans « ' + cols[vi] + ' » : rien n’y a été lu, et une absence n’est pas un zéro');
    if (illisibles > 0) bouts.push(LANG === 'en'
      ? illisibles + ' of the ' + rows.length + ' served row(s) carry a value in “' + cols[vi] + '” that is NOT a number: it was not read as zero, it was not read at all'
      : illisibles + ' des ' + rows.length + ' ligne(s) servies portent dans « ' + cols[vi] + ' » une valeur qui n’est PAS un nombre : elle n’a pas été lue comme un zéro, elle n’a pas été lue du tout');
    if (nonListees > 0) bouts.push(LANG === 'en'
      ? nonListees + ' drawn categor(ies) are not listed below — the legend stops at ' + PLAFOND_LEGENDE
      : nonListees + ' catégorie(s) dessinées ne sont pas listées ci-dessous — la légende s’arrête à ' + PLAFOND_LEGENDE);
    wrap.appendChild(noeudNonMontre(bouts));
  }
  return wrap;
}

// HEATMAP — deux dimensions + valeur ([ligne, colonne, valeur], ex `stats count by host, source`). Grille de
// cellules, intensité = valeur normalisée. Repli 2 colonnes -> heatmap 1×N (dégradé sur la seule dimension).
// CE QUE CETTE GRILLE NE MONTRE PAS, ELLE LE DIT — le même geste que `pieEl`, et par le MÊME écrivain
// (`noeudNonMontre`). DEUX pertes, toutes deux mesurées le 2026-08-27, toutes deux muettes jusque-là :
//  · UNE COUPE. La grille s'arrête à 60 lignes et 40 colonnes. Mesuré : 70 lignes servies rendaient 60
//    lignes de grille, 50 colonnes en rendaient 40, et le texte du nœud ne portait AUCUN mot de coupe —
//    le module la nommait comme un reste ouvert au lieu de la fermer, pendant que sa fonction sœur venait
//    de recevoir exactement le geste qui manquait ici. Les plafonds sont désormais NOMMÉS une seule fois
//    et la phrase les lit : elle ne peut plus dire un autre chiffre que celui qui coupe.
//  · UNE COLLISION. Deux lignes servies qui portent la MÊME paire (ligne, colonne) écrivent dans la MÊME
//    cellule, et la dernière arrivée écrase la précédente. Mesuré : `[['a',1],['a',2],['b',3]]` rend DEUX
//    cellules, `2` et `3` — la valeur `1` a DISPARU sans un mot, et la grille se présentait comme le
//    résultat complet. Ici la perte n'est pas un zéro écarté mais une valeur VRAIE : elle se compte et
//    se dit. Écraser reste le comportement — sommer inventerait un agrégat que la requête n'a pas demandé.
const PLAFOND_LIGNES_GRILLE = 60;     // au-delà, la grille ne tient plus dans le panneau
const PLAFOND_COLONNES_GRILLE = 40;   // idem en largeur ; les DEUX sont lus par la phrase qui les avoue
function heatmapEl(cols, rows, query, drill) {
  const has2 = cols.length >= 3;
  const ri = 0, ci = has2 ? 1 : 0, vi = cols.length - 1;
  const rowKeys = [], colKeys = [], rowSeen = new Set(), colSeen = new Set();
  const cell = new Map(); // "r\x1fc" -> value  (\x1f = unit separator : jamais present dans une valeur de dimension)
  let ecrasees = 0;       // lignes servies dont la cellule a été réécrite par une ligne suivante
  rows.forEach(r => {
    const rk = r[ri] == null ? '-' : String(r[ri]);
    const ck = has2 ? (r[ci] == null ? '-' : String(r[ci])) : 'valeur';
    if (!rowSeen.has(rk)) { rowSeen.add(rk); rowKeys.push(rk); }
    if (!colSeen.has(ck)) { colSeen.add(ck); colKeys.push(ck); }
    const k = rk + '\x1f' + ck;
    if (cell.has(k)) ecrasees++;
    cell.set(k, Number(r[vi]) || 0);
  });
  const max = Math.max(1, ...[...cell.values()]);
  const wrap = document.createElement('div'); wrap.className = 'heatwrap';
  const tbl = document.createElement('table'); tbl.className = 'heatmap';
  const thead = document.createElement('thead'); const htr = document.createElement('tr');
  htr.appendChild(document.createElement('th'));
  colKeys.slice(0, PLAFOND_COLONNES_GRILLE).forEach(ck => { const th = document.createElement('th'); th.textContent = ck; th.title = ck; htr.appendChild(th); });
  thead.appendChild(htr); tbl.appendChild(thead);
  const tb = document.createElement('tbody');
  rowKeys.slice(0, PLAFOND_LIGNES_GRILLE).forEach(rk => {
    const tr = document.createElement('tr');
    const rh = document.createElement('th'); rh.className = 'heatrow'; rh.textContent = rk; rh.title = rk; tr.appendChild(rh);
    colKeys.slice(0, PLAFOND_COLONNES_GRILLE).forEach(ck => {
      const v = cell.get(rk + '\x1f' + ck) || 0;
      const td = document.createElement('td'); td.className = 'heatcell';
      const alpha = v > 0 ? (0.12 + 0.88 * (v / max)) : 0;
      td.style.background = v > 0 ? `color-mix(in srgb, ${CSSV('--acc', '#2dd4bf')} ${Math.round(alpha * 100)}%, transparent)` : 'transparent';
      td.textContent = v > 0 ? String(v) : '';
      const tipTxt = `${rk}${has2 ? ' / ' + ck : ''} : ${v}`;
      td.addEventListener('mousemove', e => tipShow(tipTxt, e)); td.addEventListener('mouseleave', tipHide);
      if (v > 0) {
        if (drill) { td.style.cursor = 'pointer'; td.onclick = () => customDrill(drill, { value: rk }); }
        else if (!DIMENSIONLESS.has(cols[0])) { td.style.cursor = 'pointer'; td.onclick = () => drilldown(cols[0], rk); }
      }
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  tbl.appendChild(tb); wrap.appendChild(tbl);
  const lignesCoupees = Math.max(0, rowKeys.length - PLAFOND_LIGNES_GRILLE);
  const colonnesCoupees = Math.max(0, colKeys.length - PLAFOND_COLONNES_GRILLE);
  const bouts = [];
  if (lignesCoupees > 0) bouts.push(LANG === 'en'
    ? lignesCoupees + ' of the ' + rowKeys.length + ' grid row(s) are not shown — the grid stops at ' + PLAFOND_LIGNES_GRILLE
    : lignesCoupees + ' des ' + rowKeys.length + ' ligne(s) de la grille ne sont pas montrées — la grille s’arrête à ' + PLAFOND_LIGNES_GRILLE);
  if (colonnesCoupees > 0) bouts.push(LANG === 'en'
    ? colonnesCoupees + ' of the ' + colKeys.length + ' grid column(s) are not shown — the grid stops at ' + PLAFOND_COLONNES_GRILLE
    : colonnesCoupees + ' des ' + colKeys.length + ' colonne(s) de la grille ne sont pas montrées — la grille s’arrête à ' + PLAFOND_COLONNES_GRILLE);
  if (ecrasees > 0) bouts.push(LANG === 'en'
    ? ecrasees + ' of the ' + rows.length + ' served row(s) are carried by no cell: another row holds the SAME (row, column) pair and the last one served wins'
    : ecrasees + ' des ' + rows.length + ' ligne(s) servies ne sont portées par aucune cellule : une autre ligne porte la MÊME paire (ligne, colonne) et la dernière servie l’emporte');
  if (bouts.length) wrap.appendChild(noeudNonMontre(bouts));
  return wrap;
}

// HISTOGRAM — distribution binned d'une colonne numérique. Si les lignes portent DÉJÀ [bucket,count]
// (agrégat) on les rend en barres contiguës ; sinon on binne la dernière colonne numérique (Sturges borné).
// LE PARTAGE VIENT DE LA FORME DU RÉSULTAT, PLUS DE SON ARITÉ (mesuré le 2026-08-27). Il lisait
// `rows.length > 1 && cols.length >= 2` : un agrégat qui ne rendait qu'UNE ligne — un `stats count by host`
// sur une journée où un seul hôte a parlé — tombait dans la branche du BINNING, qui compte des VALEURS.
// Mesuré : `[['web-01', 42]]` rendait une barre pleine hauteur étiquetée « 42.0 » dont la valeur affichée,
// et l'axe, valaient **1** — la donnée servie disait 42. Ni l'une ni l'autre porte ne le voyait (la colonne
// est numérique, la figure dessine). Ce qui distingue un agrégat d'une liste de valeurs brutes est la
// PRÉSENCE d'une colonne de libellé à côté de la valeur, jamais le NOMBRE de lignes : c'est cela, et cela
// seul, qui est lu maintenant.
function histogramEl(cols, rows, query, drill) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const vi = cols.length - 1;
  const vals = rows.map(r => Number(r[vi])).filter(n => Number.isFinite(n));
  const wrap = document.createElement('div'); wrap.className = 'histwrap';
  // UNE ABSENCE SE DIT PAR LE FAIT MESURÉ, PAS PAR UNE CAUSE INVENTÉE (`P11.18-p`). Sur ZÉRO ligne, cette
  // représentation disait « aucune donnée NUMÉRIQUE » : elle attribuait à la NATURE de la colonne une
  // absence qu'elle n'avait pas mesurée — rien n'avait été servi, donc rien n'avait été lu. La phrase de
  // la nature reste, mais pour le seul cas qui l'établit : des lignes servies dont aucune valeur n'est un
  // nombre (chemin que la porte de `vizElement` ferme, et que `vizSansPorte` laisse encore atteindre).
  if (!rows.length) { wrap.appendChild(muted(LANG === 'en' ? 'no data' : 'aucune donnée')); return wrap; }
  if (!vals.length) { wrap.appendChild(muted('aucune donnée numérique')); return wrap; }
  let bins;
  if (cols.length >= 2) {
    // pré-agrégé [clé, count] -> une barre par ligne (ordre préservé).
    bins = rows.map(r => ({ label: r[0] == null ? '-' : String(r[0]), c: Number(r[vi]) || 0 }));
  } else {
    const mn = Math.min(...vals), mx = Math.max(...vals);
    const nb = Math.max(1, Math.min(24, Math.ceil(Math.log2(vals.length) + 1)));
    const w = (mx - mn) / nb || 1;
    const counts = new Array(nb).fill(0);
    vals.forEach(v => { let k = Math.floor((v - mn) / w); if (k >= nb) k = nb - 1; if (k < 0) k = 0; counts[k]++; });
    bins = counts.map((c, i) => ({ label: `${(mn + i * w).toFixed(1)}`, c }));
  }
  const W = 640, H = 200, pad = 30, n = bins.length, max = Math.max(1, ...bins.map(b => b.c));
  const svg = mk('svg'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('class', 'histchart');
  const bw = (W - 2 * pad) / n;
  bins.forEach((b, i) => {
    const h = (b.c / max) * (H - 2 * pad), x = pad + i * bw, y = H - pad - h;
    const rect = mk('rect'); rect.setAttribute('x', x + 1); rect.setAttribute('y', y); rect.setAttribute('width', Math.max(1, bw - 1)); rect.setAttribute('height', h); rect.setAttribute('fill', CSSV('--acc', '#2dd4bf'));
    const tipTxt = `${b.label} : ${b.c}`;
    rect.addEventListener('mousemove', e => tipShow(tipTxt, e)); rect.addEventListener('mouseleave', tipHide);
    if (drill) { rect.style.cursor = 'pointer'; rect.onclick = () => customDrill(drill, { value: b.label }); }
    svg.appendChild(rect);
  });
  const ax = mk('path'); ax.setAttribute('d', `M${pad},${H - pad} L${W - pad},${H - pad}`); ax.setAttribute('stroke', CSSV('--bd', '#16202e')); ax.setAttribute('fill', 'none'); svg.appendChild(ax);
  const txt = (x, y, s, a) => { const e = mk('text'); e.setAttribute('x', x); e.setAttribute('y', y); e.setAttribute('fill', CSSV('--mut', '#8aa0b4')); e.setAttribute('font-size', '10'); if (a) e.setAttribute('text-anchor', a); e.textContent = s; svg.appendChild(e); };
  if (n) { txt(pad, H - 8, bins[0].label); txt(W - pad, H - 8, bins[n - 1].label, 'end'); txt(3, pad, String(max)); }
  return svg;
}

// `table *` & co : `fields` est un JSON (les clés varient par event/source -> pas de schéma fixe
// possible côté SQL). À L'AFFICHAGE on le DÉCOMPOSE en colonnes : union des clés vues sur la page,
// triées, en sautant celles déjà en colonne réelle (ex src_ip promu) -> pas de doublon. Rien de perdu :
// la ligne brute reste dans `message` + le détail (clic). No-op si pas de colonne `fields`.
function expandFields(cols, rows) {
  const fi = cols.indexOf('fields');
  if (fi < 0) return { cols, rows };
  const base = new Set(cols.filter((_, i) => i !== fi));
  const keys = [], seen = new Set();
  const parsed = rows.map(r => {
    let o = null; try { o = r[fi] ? JSON.parse(r[fi]) : null; } catch (e) { o = null; }
    if (o && typeof o === 'object' && !Array.isArray(o)) for (const k of Object.keys(o))
      if (!seen.has(k) && !base.has(k) && o[k] != null && o[k] !== '') { seen.add(k); keys.push(k); }
    return o;
  });
  if (!keys.length) return { cols, rows };   // fields vide partout -> on garde la colonne telle quelle
  keys.sort();
  const flat = v => (v == null ? null : (typeof v === 'object' ? JSON.stringify(v) : v));
  const ncols = []; cols.forEach((c, i) => { if (i === fi) keys.forEach(k => ncols.push(k)); else ncols.push(c); });
  const nrows = rows.map((r, ri) => {
    const o = parsed[ri] || {}, nr = [];
    cols.forEach((c, i) => { if (i === fi) keys.forEach(k => nr.push(flat(o[k]))); else nr.push(r[i]); });
    return nr;
  });
  return { cols: ncols, rows: nrows };
}

function closeColsMenu() { if (S._colsMenuClose) { const f = S._colsMenuClose; S._colsMenuClose = null; S._colsMenuOwner = null; f(); } }

// COMPARATEUR DE COLONNE PARTAGÉ (tableEl + pagedList — BATCH 1). `get(row)` -> valeur de la colonne.
// Détermine le type UNE fois sur l'échantillon : IPv4 -> tri par octets (14.x < 102.x, pas lexical) ;
// sinon numérique si toutes les valeurs le sont ; sinon alpha (localeCompare). Renvoie un comparateur
// ASCENDANT (a,b)=>n ; l'appelant applique le sens (× dir). Sémantique identique à l'ancien tri inline.
// `opts` (optionnel) — PAGINATION CLIENT du DOM (BATCH panneaux) : { pager:true, pageSize, total, totalCapped }.
// GÉNÉRIQUE (aucun nom de champ en dur) : quand `pager` est vrai, on ne pose dans le <tbody> QUE la tranche de
// la page courante (tri/masquage portent toujours sur l'ensemble en mémoire), enveloppée d'un pager numéroté
// makePager (haut+bas, auto-caché si <=1 page). Sert les panneaux d'AGRÉGATION (groupes déjà en mémoire) + les
// listes de lignes non serveur-paginées : le DOM ne tient qu'une page (scale des milliers de groupes). `total`
// = vrai total affiché (défaut = rows.length ; un count_only NON plafonné peut le remplacer via re-rendu).
// SANS `opts` : comportement STRICTEMENT INCHANGÉ (Explore, aperçus) — byte-identique.
function tableEl(cols, rows, query, drill, opts) {
  ({ cols, rows } = expandFields(cols, rows));   // décompose la colonne `fields` (JSON) en colonnes individuelles
  const showNum = rows.length > 1;   // colonne « # » (numéro de ligne) inutile s'il n'y a qu'une seule ligne
  const key = unitKeyFor(cols, query), last = cols.length - 1;
  const order = cols.map((_, i) => i);   // ordre d'affichage (indices d'origine) -> reordonnable
  const widths = {};                     // largeurs par colonne d'origine (px)
  let sortIdx = -1, sortDir = 1;         // colonne triee + sens (1 asc / -1 desc)
  // SÉLECTEUR DE COLONNES : couverture (% de lignes non vides) par colonne ; si la table est large
  // (multi-sources), on MASQUE par défaut les colonnes creuses hors cœur -> propre sans scoper la requête.
  const cover = cols.map((_, i) => rows.length ? rows.reduce((n, r) => n + (r[i] != null && r[i] !== '' ? 1 : 0), 0) / rows.length : 1);
  const CORE = new Set(['ts', '_time', 'time', 'bucket', 'source', 'host', 'message', 'src_ip', 'dst_ip']);
  const hidden = new Set();
  if (order.length > 12) cols.forEach((c, i) => { if (!CORE.has(c) && cover[i] < 0.5) hidden.add(i); });
  const vcount = () => order.filter(oi => !hidden.has(oi)).length;
  const id = 'cm' + Math.random().toString(36).slice(2, 8);
  let colsBtn = null;
  const tbl = document.createElement('table'); tbl.className = 'qtable';
  // 1 SEULE colonne de contenu (ex. `| table message`) : on dé-plafonne la cellule pour que la ligne
  // longue soit LISIBLE par défilement horizontal (le conteneur .qresult scrolle) — sans avoir à cliquer.
  if (cols.length === 1) tbl.classList.add('onecol');
  const thead = document.createElement('thead'), tb = document.createElement('tbody');
  tbl.append(thead, tb);
  const TIMECOLS = new Set(['ts', '_time', 'bucket']);
  const fmtCell = (v, oi) => {
    if (TIMECOLS.has(cols[oi]) && v > 1e9 && v < 2e10) return fmtTs(Number(v));   // epoch -> date lisible (auditd & co, plus d'epoch brut)
    return (oi === last && key) ? fmtVal(key, v) : (v == null ? '-' : String(v));
  };
  const chevron = up => `<svg class="ic" viewBox="0 0 24 24"><path d="${up ? 'M6 15l6-6 6 6' : 'M6 9l6 6 6-6'}"/></svg>`;
  // PAGINATION CLIENT (opt-in via opts.pager) — état LOCAL à cette table (chaque panneau est indépendant).
  const pg = (opts && opts.pager) ? { page: 0, pageSize: opts.pageSize || 50, total: (opts.total != null ? opts.total : rows.length), shown: 0, totalCapped: !!opts.totalCapped } : null;
  const topPager = document.createElement('div'), botPager = document.createElement('div');
  function syncPagers() {
    if (!pg) return;
    const go = p => { pg.page = Math.max(0, p); build(); };
    const a = makePager(pg, go); topPager.replaceChildren(); if (a) topPager.appendChild(a);
    const b = makePager(pg, go); botPager.replaceChildren(); if (b) botPager.appendChild(b);
  }
  function withPagers(inner) {
    const cont = document.createElement('div'); cont.className = 'panelpaged';
    cont.append(topPager, inner, botPager); return cont;
  }
  function build() {
    // --- en-tetes : tri (clic) + reordonner (glisser) + redimensionner (poignee) ---
    const htr = document.createElement('tr');
    if (showNum) { const numTh = document.createElement('th'); numTh.className = 'numcol'; numTh.textContent = '#'; htr.appendChild(numTh); }   // colonne numero de ligne (masquée si 1 seule ligne)
    order.forEach((oi, pos) => {
      if (hidden.has(oi)) return;   // colonne masquée via le sélecteur
      const th = document.createElement('th'); th.draggable = true;
      const lab = document.createElement('span'); lab.textContent = cols[oi]; th.appendChild(lab);
      if (oi === sortIdx) { const ar = document.createElement('span'); ar.className = 'sortar'; ar.innerHTML = chevron(sortDir > 0); th.appendChild(ar); }
      if (widths[oi]) th.style.width = widths[oi] + 'px';
      th.onclick = e => { if (e.target.classList.contains('rsz')) return; if (sortIdx === oi) sortDir = -sortDir; else { sortIdx = oi; sortDir = 1; } build(); };
      th.ondragstart = e => e.dataTransfer.setData('text/plain', String(pos));
      th.ondragover = e => { e.preventDefault(); th.classList.add('dragover'); };
      th.ondragleave = () => th.classList.remove('dragover');
      th.ondrop = e => { e.preventDefault(); th.classList.remove('dragover'); const from = Number(e.dataTransfer.getData('text/plain')); if (Number.isInteger(from) && from !== pos) { const [m] = order.splice(from, 1); order.splice(pos, 0, m); build(); } };
      const rsz = document.createElement('span'); rsz.className = 'rsz'; th.appendChild(rsz);
      rsz.onmousedown = e => {
        e.preventDefault(); e.stopPropagation();
        const x0 = e.clientX, w0 = th.offsetWidth;
        const mv = ev => { widths[oi] = Math.max(40, w0 + ev.clientX - x0); th.style.width = widths[oi] + 'px'; };
        const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
      };
      htr.appendChild(th);
    });
    thead.replaceChildren(htr);
    // --- corps : tri selon la colonne (comparateur PARTAGÉ colComparator : IPv4/numérique/alpha) ---
    let view = rows;
    if (sortIdx >= 0) {
      const cmp = colComparator(rows, r => r[sortIdx]);
      view = [...rows].sort((a, b) => cmp(a, b) * sortDir);
    }
    // PAGINATION CLIENT : le tri porte sur TOUT l'ensemble ; on ne rend que la tranche de la page courante.
    if (pg) { if (pg.page * pg.pageSize >= view.length && view.length) pg.page = Math.floor((view.length - 1) / pg.pageSize); view = view.slice(pg.page * pg.pageSize, pg.page * pg.pageSize + pg.pageSize); pg.shown = view.length; syncPagers(); }
    const numBase = pg ? pg.page * pg.pageSize : 0;
    tb.replaceChildren(...view.map((row, ri) => {
      const tr = document.createElement('tr');
      if (showNum) { const numTd = document.createElement('td'); numTd.className = 'numcol'; numTd.textContent = String(numBase + ri + 1); tr.appendChild(numTd); }   // numero de ligne (suit le tri ; offset par page)
      order.forEach(oi => { if (hidden.has(oi)) return; const td = document.createElement('td'); td.textContent = fmtCell(row[oi], oi); tr.appendChild(td); });
      tr.style.cursor = 'pointer';
      tr.title = drill ? 'Cliquer pour exécuter le drill du panneau' : (DIMENSIONLESS.has(cols[0]) ? 'Cliquer pour voir tous les détails' : `Cliquer pour voir les événements ${cols[0]}=${row[0]}`);
      // P11.4-h — LA LIGNE ENTIÈRE EST CLIQUABLE, ET C'EST ELLE QUI AVALAIT LA SÉLECTION. Un
      // glisser-sélectionner dans une cellule se termine par un `mouseup` dans la ligne : le clic partait,
      // le drilldown remplaçait la vue, et le fragment sélectionné disparaissait avec elle. Le geste
      // partagé rend le clic à sa place — il se retire quand une sélection vient d'être faite ICI, et
      // seulement ici (une sélection ailleurs dans la page ne gèle rien).
      clicQuiRespecteLaSelection(tr, () => {
        if (drill) { const c = { value: row[0] }; if (DIMENSIONLESS.has(cols[0])) c.from = Number(row[0]); return customDrill(drill, c); }
        if (!DIMENSIONLESS.has(cols[0])) return drilldown(cols[0], row[0]);
        const nx = tr.nextSibling;
        if (nx && nx.classList && nx.classList.contains('rowdetail')) { nx.remove(); return; }
        const dtr = document.createElement('tr'); dtr.className = 'rowdetail';
        const td = document.createElement('td'); td.colSpan = vcount() + (showNum ? 1 : 0);
        const dl = document.createElement('dl'); dl.className = 'kvdetail';
        let nHidden = 0;
        cols.forEach((c, i) => { const sv = row[i] == null ? '' : String(row[i]).trim(); if (sv === '' || sv === '-') { nHidden++; return; } const dt = document.createElement('dt'); dt.textContent = c; const dd = document.createElement('dd'); dd.textContent = sv; dl.append(dt, dd); });
        td.appendChild(dl);
        if (nHidden) { const note = document.createElement('div'); note.className = 'muted'; note.style.cssText = 'font-size:11px;margin-top:6px'; note.textContent = '(' + nHidden + ' champ(s) vide(s) masqué(s))'; td.appendChild(note); }
        dtr.appendChild(td); tr.after(dtr);
      });
      return tr;
    }));
    if (colsBtn) colsBtn.textContent = `Colonnes ${vcount()}/${order.length} ▾`;
  }
  build();
  if (order.length <= 7) return pg ? withPagers(tbl) : tbl;   // peu de colonnes -> pas de sélecteur
  const wrap = document.createElement('div'); wrap.className = 'qtblwrap';
  const bar = document.createElement('div'); bar.className = 'qtblbar';
  colsBtn = document.createElement('button'); colsBtn.type = 'button'; colsBtn.className = 'colsbtn';
  colsBtn.textContent = `Colonnes ${vcount()}/${order.length} ▾`;
  colsBtn.onclick = (ev) => {
    ev.stopPropagation();
    const wasMine = S._colsMenuOwner === id;
    closeColsMenu();
    if (wasMine) return;                                  // re-clic = ferme (toggle)
    S._colsMenuOwner = id;
    const menu = document.createElement('div'); menu.className = 'colsmenu';
    order.forEach(oi => {
      const lab = document.createElement('label');
      const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !hidden.has(oi);
      cb.onchange = () => { if (cb.checked) hidden.delete(oi); else hidden.add(oi); build(); };
      const nm = document.createElement('span'); nm.className = 'colsnm'; nm.textContent = cols[oi];
      const pc = document.createElement('span'); pc.className = 'colspc'; pc.textContent = Math.round(cover[oi] * 100) + '%';
      lab.append(cb, nm, pc); menu.appendChild(lab);
    });
    const allb = document.createElement('button'); allb.type = 'button'; allb.className = 'colsall'; allb.textContent = 'Tout afficher';
    allb.onclick = () => { hidden.clear(); build(); menu.querySelectorAll('input').forEach(c => c.checked = true); };
    menu.appendChild(allb);
    const r = colsBtn.getBoundingClientRect();
    menu.style.right = (window.innerWidth - r.right) + 'px';
    document.body.appendChild(menu);
    // `P11.22-z` — LA HAUTEUR VIENT DE L'ESPACE QUI EXISTE SOUS LE BOUTON, pas d'une fraction d'écran.
    // Ce menu est le seul de la console à s'ouvrir sous une ancre qui peut siéger N'IMPORTE OÙ : la barre
    // d'un tableau de résultats vit aussi dans un panneau de dashboard. Le geste partagé pose la borne
    // réelle et bascule au-dessus du bouton quand il n'y a plus de place dessous (core.js).
    bornerLePopoverSousSonAncre(menu, r);
    const onclose = e => { if (!menu.contains(e.target) && e.target !== colsBtn) closeColsMenu(); };
    // `P11.22-z` — LE CAPTEUR RECEVAIT LE DÉFILEMENT DE SA PROPRE LISTE. Posé sur le document en phase de
    // CAPTURE, il voit passer TOUT événement `scroll` — y compris celui qu'émet ce menu quand l'exploitant
    // le fait défiler (un `scroll` ne remonte pas, mais il DESCEND : la capture le livre au document avant
    // la cible). La liste se refermait donc sous le doigt, ce qui se lit du poste « la liste ne défile
    // pas » et rend les dernières colonnes inatteignables, sans erreur et sans un mot. Ce capteur n'a
    // qu'un objet : la page a bougé SOUS un menu ancré en coordonnées de fenêtre. Un défilement né DANS
    // le menu ne déplace pas son ancre et ne le concerne pas. Mesuré le 2026-08-30 : le menu se détachait
    // du document au premier cran de molette posé sur lui.
    const onscroll = e => { if (e && e.target && menu.contains(e.target)) return; closeColsMenu(); };
    S._colsMenuClose = () => { menu.remove(); document.removeEventListener('click', onclose); document.removeEventListener('scroll', onscroll, true); };
    setTimeout(() => { document.addEventListener('click', onclose); document.addEventListener('scroll', onscroll, true); }, 0);
  };
  bar.appendChild(colsBtn); wrap.append(bar, tbl);
  return pg ? withPagers(wrap) : wrap;
}

function statEl(cols, rows, query, drill) {
  const key = unitKeyFor(cols, query);
  const v = rows.length ? rows[0][rows[0].length - 1] : null;
  const d = document.createElement('div'); d.className = 'statbig'; d.textContent = fmtVal(key, v);
  if (query || drill) {
    d.style.cursor = 'pointer';
    d.title = drill ? 'Cliquer pour exécuter le drill du panneau' : 'Cliquer pour voir ce qui se cache derrière ce chiffre';
    d.onclick = () => statDrill(query, drill);
  }
  return noeudUneSeuleLigne(d, rows);
}

function barEl(cols, rows, query, drill) {
  const vi = cols.length - 1, key = unitKeyFor(cols, query);
  const nums = rows.map(r => Number(r[vi]) || 0);
  const max = Math.max(1, ...nums);
  const wrap = document.createElement('div'); wrap.className = 'bars';
  rows.forEach((r, i) => {
    const row = document.createElement('div'); row.className = 'barrow';
    const lab = document.createElement('span'); lab.className = 'barlabel'; lab.textContent = String(r[0]);
    const track = document.createElement('div'); track.className = 'bartrack';
    const fill = document.createElement('div'); fill.className = 'barfill'; fill.style.width = (nums[i] / max * 100) + '%';
    track.appendChild(fill);
    const val = document.createElement('span'); val.className = 'barval'; val.textContent = fmtVal(key, r[vi]);
    const tipTxt = `${r[0]} : ${fmtVal(key, r[vi])}`;
    row.addEventListener('mousemove', e => tipShow(tipTxt, e));
    row.addEventListener('mouseleave', tipHide);
    if (drill) { row.style.cursor = 'pointer'; row.title = 'Cliquer pour exécuter le drill du panneau'; row.onclick = () => customDrill(drill, { value: r[0] }); }
    else if (!DIMENSIONLESS.has(cols[0])) { row.style.cursor = 'pointer'; row.title = 'Cliquer pour voir les événements'; row.onclick = () => drilldown(cols[0], r[0]); }
    row.append(lab, track, val); wrap.appendChild(row);
  });
  return wrap;
}

function fmtMaybeTime(v) {
  const n = Number(v);
  if (n > 1e9 && n < 2e10) return new Date(n * 1000).toLocaleTimeString(LOC, { hour: '2-digit', minute: '2-digit', ...tzOpts() });
  return String(v);
}

function lineEl(cols, rows, query, drill) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const W = 640, H = 200, pad = 30, key = unitKeyFor(cols, query);
  const xs = rows.map(r => Number(r[0]) || 0);
  const ys = rows.map(r => Number(r[r.length - 1]) || 0);
  const ymax = Math.max(1, ...ys), xmin = Math.min(...xs), xmax = Math.max(...xs);
  const sx = x => pad + (xmax > xmin ? (x - xmin) / (xmax - xmin) : 0.5) * (W - 2 * pad);
  const sy = y => H - pad - (y / ymax) * (H - 2 * pad);
  const svg = mk('svg'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('class', 'linechart');
  const txt = (x, y, s, a) => { const e = mk('text'); e.setAttribute('x', x); e.setAttribute('y', y); e.setAttribute('fill', CSSV('--mut', '#8aa0b4')); e.setAttribute('font-size', '10'); e.setAttribute('text-anchor', a || 'start'); e.textContent = s; svg.appendChild(e); };
  const axis = mk('path'); axis.setAttribute('d', `M${pad},${pad} L${pad},${H - pad} L${W - pad},${H - pad}`); axis.setAttribute('stroke', CSSV('--bd', '#16202e')); axis.setAttribute('fill', 'none'); svg.appendChild(axis);
  if (rows.length) {
    const pts = rows.map((r, i) => `${sx(xs[i])},${sy(ys[i])}`);
    const area = mk('polygon');
    area.setAttribute('points', `${sx(xs[0])},${H - pad} ${pts.join(' ')} ${sx(xs[xs.length - 1])},${H - pad}`);
    area.setAttribute('fill', CSSV('--acc-soft', 'rgba(45,212,191,.16)')); svg.appendChild(area);
    const poly = mk('polyline'); poly.setAttribute('points', pts.join(' ')); poly.setAttribute('fill', 'none'); poly.setAttribute('stroke', CSSV('--acc', '#2dd4bf')); poly.setAttribute('stroke-width', '2'); svg.appendChild(poly);
    rows.forEach((r, i) => { const c = mk('circle'); c.setAttribute('cx', sx(xs[i])); c.setAttribute('cy', sy(ys[i])); c.setAttribute('r', rows.length === 1 ? '4' : '2.5'); c.setAttribute('fill', CSSV('--acc', '#2dd4bf')); svg.appendChild(c); });
    txt(3, pad, fmtVal(key, ymax));
    txt(pad, H - 8, fmtMaybeTime(xs[0]));
    if (xs.length > 1) txt(W - pad, H - 8, fmtMaybeTime(xs[xs.length - 1]), 'end');
  }
  if (rows.length > 1 && xmin > 1e9 && xmax < 2e10) { // axe X temporel -> zoom par drag
    attachZoom(svg, W, vx => xmin + Math.max(0, Math.min(1, (vx - pad) / (W - 2 * pad))) * (xmax - xmin));
  }
  attachTip(svg, W, vx => { let b = 0, bd = 1e9; for (let i = 0; i < xs.length; i++) { const d = Math.abs(sx(xs[i]) - vx); if (d < bd) { bd = d; b = i; } } return (xs.length && bd < 40) ? `${fmtMaybeTime(xs[b])} : ${fmtVal(key, ys[b])}` : ''; });
  if (rows.length) {
    // crosshair + point au survol ; clic -> evenements du bucket
    const cross = mk('line'); cross.setAttribute('y1', pad); cross.setAttribute('y2', H - pad); cross.setAttribute('stroke', CSSV('--mut', '#8aa0b4')); cross.setAttribute('stroke-dasharray', '3 3'); cross.style.display = 'none'; svg.appendChild(cross);
    const mark = mk('circle'); mark.setAttribute('r', '4.5'); mark.setAttribute('fill', CSSV('--acc', '#2dd4bf')); mark.setAttribute('stroke', CSSV('--card', '#0c1422')); mark.setAttribute('stroke-width', '2'); mark.style.display = 'none'; svg.appendChild(mark);
    let hi = -1;
    const vbx = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
    svg.addEventListener('mousemove', e => {
      const vx = vbx(e); let b = 0, bd = 1e9;
      for (let i = 0; i < xs.length; i++) { const d = Math.abs(sx(xs[i]) - vx); if (d < bd) { bd = d; b = i; } }
      if (bd < 60) { hi = b; const X = sx(xs[b]), Y = sy(ys[b]); cross.setAttribute('x1', X); cross.setAttribute('x2', X); cross.style.display = ''; mark.setAttribute('cx', X); mark.setAttribute('cy', Y); mark.style.display = ''; if (xs[b] > 1e9 && timeZoomEnabled()) svg.style.cursor = 'pointer'; }
      else { hi = -1; cross.style.display = 'none'; mark.style.display = 'none'; }
    });
    svg.addEventListener('mouseleave', () => { hi = -1; cross.style.display = 'none'; mark.style.display = 'none'; });
    svg.addEventListener('click', () => {
      if (svg._zoomed) { svg._zoomed = false; return; }
      if (hi < 0 || xs[hi] <= 1e9) return;
      const span = xs.length > 1 ? xs[1] - xs[0] : 60;
      if (drill) customDrill(drill, { from: xs[hi], to: xs[hi] + span, value: ys[hi] });   // drill champ/valeur : partout (cœur d'Explore)
      else if (timeZoomEnabled()) drillTime(xs[hi], span);                                  // zoom-temporel : dashboards uniquement
    });
  }
  return svg;
}

function renderViz() {
  if (!S.lastResult) return;
  // `P11.18-a` : Explore n'a pas d'objet persistant -> la clé du réglage est la SIGNATURE des colonnes
  // servies (`cleDeReglage` avec un identifiant de panneau nul). Sans réglage mémorisé, `noeudsDeVizReglee`
  // rend l'appel `vizElement` d'origine, sur les colonnes et les lignes d'origine.
  $('#qresult').replaceChildren(...noeudsDeVizReglee(($('#viz') && $('#viz').value) || 'table', S.lastResult.columns, S.lastResult.rows, $('#sql') ? $('#sql').value : '', '', 0, renderViz));
}

// --- affichage unifie : evenements bruts OU table/viz selon la requete ---
function addSearchFilter(field, value) {
  let v = value;
  if (field === 'severity') { const n = SEV.indexOf(value); if (n >= 0) v = n; }
  const q = $('#sql').value.trim();
  const pipe = q.indexOf('|');
  let head = (pipe < 0 ? q : q.slice(0, pipe)).trim();
  if (!/^\s*search\b/i.test(head)) head = ('search ' + head).trim();
  const tail = pipe < 0 ? '' : ' ' + q.slice(pipe);
  $('#sql').value = `${head} ${field}:${v}`.replace(/\s+/g, ' ').trim() + tail;
  runQuery();
}

function facetBlock(rows, idx, field, label) {
  const counts = new Map();
  rows.forEach(r => { const raw = (r[idx] == null || r[idx] === '') ? null : r[idx]; counts.set(raw, (counts.get(raw) || 0) + 1); });
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const block = document.createElement('div'); block.className = 'fldblock';
  block.appendChild(Object.assign(document.createElement('div'), { className: 'fldname', textContent: label }));
  top.forEach(([raw, c]) => {
    const disp = raw == null ? '-' : (field === 'severity' ? sev(raw) : String(raw));
    const row = document.createElement('button'); row.className = 'fldval';
    const s = document.createElement('span'); s.textContent = disp;
    const cc = document.createElement('span'); cc.className = 'fldc'; cc.textContent = c;
    row.append(s, cc);
    if (raw != null) row.onclick = () => addSearchFilter(field, field === 'severity' ? sev(raw) : raw);
    block.appendChild(row);
  });
  return block;
}

function renderEvents(host, cols, rows) {
  const ix = n => cols.indexOf(n);
  const tsI = ix('ts'), srcI = ix('source'), hostI = ix('host'), sevI = ix('severity'), ipI = ix('src_ip'), msgI = ix('message'), fldI = ix('fields');
  host.replaceChildren();
  if (!rows.length) { host.appendChild(muted('aucun evenement sur la fenetre')); return; }
  const tl = document.createElement('div'); tl.className = 'timeline';
  if (tsI >= 0) tl.appendChild(timelineEl(rows.map(r => ({ ts: Number(r[tsI]) }))));
  host.appendChild(tl);
  const body = document.createElement('div'); body.className = 'srchbody';
  const fields = document.createElement('aside'); fields.className = 'fields';
  fields.appendChild(Object.assign(document.createElement('div'), { className: 'fldcount', textContent: `${rows.length} evenement(s)` }));
  // facettes = TOUS les champs (cœur d'abord, puis tout le reste issu de `fields` aplati) — facetBlock plafonne déjà à 8 valeurs/champ.
  const { cols: fcols, rows: frows } = expandFields(cols, rows);
  const FLAB = { source: 'source', host: 'hote', severity: 'severite', src_ip: 'IP source', dst_ip: 'IP dest', category: 'categorie' };
  const FSKIP = new Set(['ts', '_time', 'bucket', 'message', 'fields', 'id', 'dedup', 'raw']);
  const FCORE = ['source', 'host', 'severity', 'src_ip'];
  const facetCols = [];
  FCORE.forEach(c => { if (fcols.includes(c)) facetCols.push(c); });
  fcols.forEach(c => { if (!FCORE.includes(c) && !FSKIP.has(c)) facetCols.push(c); });
  let nFacets = 0;
  for (const c of facetCols) {
    if (nFacets >= 50) break;
    const fi = fcols.indexOf(c);
    if (fi < 0 || !frows.some(r => r[fi] != null && r[fi] !== '')) continue;   // saute les colonnes vides
    fields.appendChild(facetBlock(frows, fi, c, FLAB[c] || c));
    nFacets++;
  }
  const ev = document.createElement('div'); ev.className = 'events';
  // bouton "voir le mail complet" : source=mail + champs structures (account/fileid), ADMIN seulement
  const mailBtn = r => {
    if (!S.isAdmin || srcI < 0 || r[srcI] !== 'mail' || fldI < 0 || !r[fldI]) return '';
    try { const f = JSON.parse(r[fldI]); if (f && f.account && f.fileid) return `<button class="mailbtn" data-acct="${esc(f.account)}" data-folder="${esc(f.folder || 'INBOX')}" data-fileid="${esc(f.fileid)}" title="Voir le mail complet (admin, audité)">${ic('ext')}</button>`; } catch (e) {}
    return '';
  };
  body.append(fields, ev); host.appendChild(body);
  // pagination SERVEUR : `rows` = UNE page ; le pager (makePager, basé sur le total COUNT) RE-FETCH la
  // page cliquée via evLoad -> le navigateur ne tient jamais qu'une page (scale 1M+).
  ev.innerHTML = rows.map((r, i) => `<div class="logline sev-${sevI >= 0 ? r[sevI] : 0}" data-i="${i}" title="Cliquer pour voir tous les détails"><time>${fmtTs(tsI >= 0 ? r[tsI] : 0)}</time><span class="src">${esc(srcI >= 0 ? r[srcI] : '')}</span><span class="logmeta">${hostI >= 0 && r[hostI] ? `<span class="hostchip">${esc(r[hostI])}</span>` : ''}${ipI >= 0 && r[ipI] ? `<span class="ipwrap"><span class="ipchip" title="${esc(r[ipI])}">${esc(r[ipI])}</span><button class="banbtn" data-ip="${esc(r[ipI])}" title="Creer une action ban_ip">${ic('ban')}</button></span>` : ''}${mailBtn(r)}<span class="logmsg">${esc(msgI >= 0 ? r[msgI] : '')}</span></span></div>`).join('');
  ev.querySelectorAll('.banbtn').forEach(b => b.onclick = () => banIp(b.dataset.ip));
  ev.querySelectorAll('.mailbtn').forEach(b => b.onclick = () => mailBody(b.dataset.acct, b.dataset.folder, b.dataset.fileid));
  // clic sur une ligne d'événement -> déplie/replie le DÉTAIL COMPLET (tous les champs, `fields` JSON aplati
  // via expandFields = fcols/frows) sous la ligne. Même modèle « kvdetail » que la vue TABLE (tableEl). Les
  // clics sur un bouton interne (ban / mail / case) NE déplient PAS (ils gardent leur action propre).
  ev.addEventListener('click', e => {
    if (e.target.closest('button, a')) return;
    const line = e.target.closest('.logline'); if (!line || !ev.contains(line)) return;
    const nx = line.nextElementSibling;
    if (nx && nx.classList && nx.classList.contains('logdetail')) { nx.remove(); line.classList.remove('open'); return; }
    ev.querySelectorAll('.logdetail').forEach(d => d.remove());           // un seul détail ouvert à la fois
    ev.querySelectorAll('.logline.open').forEach(l => l.classList.remove('open'));
    const fr = frows[Number(line.dataset.i)]; if (!fr) return;
    const det = document.createElement('div'); det.className = 'logdetail';
    const dl = document.createElement('dl'); dl.className = 'kvdetail';
    let nHidden = 0;
    fcols.forEach((c, ci) => {
      let v = fr[ci]; const sv = v == null ? '' : String(v).trim();
      if (sv === '' || sv === '-') { nHidden++; return; }
      const disp = (c === 'ts' || c === '_time' || c === 'bucket') && Number(v) > 1e9 && Number(v) < 2e10 ? fmtTs(Number(v)) : sv;
      const dt = document.createElement('dt'); dt.textContent = c;
      const dd = document.createElement('dd'); dd.textContent = disp;
      dl.append(dt, dd);
    });
    det.appendChild(dl);
    if (nHidden) { const note = document.createElement('div'); note.className = 'muted'; note.style.cssText = 'font-size:11px;margin-top:6px'; note.textContent = '(' + nHidden + ' champ(s) vide(s) masqué(s))'; det.appendChild(note); }
    line.classList.add('open'); line.after(det);
  });
  const evGo = p => { S.evState.page = p; evLoad(); };
  const evTop = makePager(S.evState, evGo), evBot = makePager(S.evState, evGo);
  if (evTop) ev.insertBefore(evTop, ev.firstChild);
  if (evBot) ev.appendChild(evBot);
}

// PAGER PARTAGÉ (BATCH 1) — Explore (events/table) + listes pagedList. `state`={page,pageSize,total,shown}
// (total<0 = inconnu). Renvoie un NŒUD `.evpager` (mêmes classes/CSS que l'ancien evPagerHtml) OU null si
// une seule page (total<=pageSize) -> auto-caché, gracieux pour le petit volume. `onGo(page0based)` navigue.
// table PAGINÉE (| table, | fields, ou résultat non-événementiel) : pager + tableEl (content-visibility gère le DOM)
function renderTablePaged(host, cols, rows) {
  host.replaceChildren();
  const go = p => { S.evState.page = p; evLoad(); };
  const top = makePager(S.evState, go);
  if (top) host.appendChild(top);
  host.appendChild(tableEl(cols, rows, S.evState.q));
  const bot = makePager(S.evState, go);
  if (bot) host.appendChild(bot);
}

const evPageSize = () => { const s = $('#qsize'); return s ? (Number(s.value) || 100) : 100; };

// KEYSET (#28) — COUNT total asynchrone (SANS plafond) : appelé UNE fois par requête, en parallèle de la 1re page,
// pour renseigner « N résultats · page X / N » + le pager numéroté, sans ralentir l'affichage. -1 si watchdog.
async function exploreCount(q, isSoql, from, to) {
  try {
    const body = isSoql ? { soql: q } : { sql: q };
    body.from = from; body.to = to; body.count_only = true; body.interactive = true;
    const r = await fetch('/api/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) return -1;
    const j = await r.json();
    return (typeof j.total === 'number') ? j.total : -1;
  } catch (e) { return -1; }
}

// COUNT total NON PLAFONNÉ générique (réutilise le MÊME endpoint /api/query count_only qu'Explore) pour TOUTE
// surface — panneaux inclus. Budget AUTO (pas interactive) : protège les panneaux (5 s). Masques/authorizer
// inchangés (un COUNT compte des LIGNES). -1 si watchdog/erreur -> l'appelant garde le total inline. Générique :
// pour une agrégation, wrappe le SELECT ... GROUP BY -> renvoie le VRAI nombre de GROUPES (pas de groupe caché).
async function queryCount(query, isSoql, from, to) {
  try {
    const b = isSoql ? { soql: query } : { sql: query };
    b.from = from; b.to = to; b.count_only = true;
    const r = await fetch('/api/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
    if (!r.ok) return -1;
    const j = await r.json();
    return (typeof j.total === 'number') ? j.total : -1;
  } catch (e) { return -1; }
}
// Re-render la page courante (events/table) avec le pager mis à jour — appelé quand le COUNT async fixe le total
// (le pager passe alors NUMÉROTÉ « X / N » via makePager) SANS refetch (réutilise colonnes/lignes déjà chargées).
function rerenderExplorePager() {
  if (!S.evState.lastCols) return;
  if (S.evState.lastForceTable) renderTablePaged($('#qresult'), S.evState.lastCols, S.evState.lastRows);
  else renderEvents($('#qresult'), S.evState.lastCols, S.evState.lastRows);
}

// charge UNE page d'events depuis le SERVEUR (curseur keyset ou LIMIT/OFFSET) — re-fetch à chaque changement de page/taille
async function evLoad() {
  S.evState.pageSize = evPageSize();
  const q = S.evState.q, isSoql = S.evState.isSoql, limit = S.evState.pageSize;
  const keyset = !!S.evState.keyset;                                   // KEYSET (#28) : search GXQL sans pipe -> curseur (ts,id), parcours INTÉGRAL sans plafond
  const cursor = keyset ? ((S.evState.cursors && S.evState.cursors[S.evState.page]) || null) : null;   // curseur pour ATTEINDRE la page courante (séquentiel)
  const jumpOff = (keyset && !cursor && S.evState.page > 0) ? S.evState.page * S.evState.pageSize : 0;  // page non atteinte en séquentiel (clic numéro / dernière) -> saut OFFSET ponctuel
  const offset = keyset ? jumpOff : S.evState.page * S.evState.pageSize;
  const sig = exploreSig(q, isSoql, limit, keyset ? ('k' + S.evState.page + (cursor ? 'c' : 'o')) : offset);
  if (S.exploreInflight && S.exploreInflight.sig === sig) return;   // dédup : requête identique déjà en vol -> on ignore
  cancelInflight();                                             // différente -> abort + /api/cancel de l'ancienne, puis relance
  const qid = nextQid(), ctrl = new AbortController();
  S.exploreInflight = { qid, sig, ctrl };
  setRunning(true); renderQBadge(null);
  $('#qstats').textContent = 'exécution…';
  const t0 = performance.now();
  try {
    // `P10.5-g` — LA FENÊTRE DU PARCOURS, GELÉE (cf. le site qui la capture). Les deux bornes viennent
    // de `S.evState.win`, jamais de l'horloge : le curseur émis pour la page k n'a de sens que sur la
    // fenêtre qui l'a numéroté. `P11.18-r` reste tenu — l'Explore RÈGLE cet intervalle et l'AFFICHE
    // (#zoombadge), il le PASSE, il ne l'hérite pas ; il le passe simplement figé pour le parcours.
    const win = S.evState.win || { from: exploreFrom(), to: exploreTo() };
    const opts = { qid, signal: ctrl.signal, to: win.to };
    if (keyset) { opts.keyset = true; if (cursor) opts.cursor = cursor; else if (jumpOff) opts.offset = jumpOff; }   // curseur (séquentiel) OU offset (saut) ; sinon 1re page
    const j = await runQ(q, isSoql, win.from, limit, offset, opts);
    if (!S.exploreInflight || S.exploreInflight.qid !== qid) return;   // supersédée (autre requête lancée) -> on ignore le résultat périmé
    if (j.error) { if (reprendreSansCurseur(j)) { evLoad(); return; } showQError(j.error); return; }
    S.evState.repriseSansCurseurFaite = false;   // une page SERVIE réarme la reprise pour un refus ultérieur
    const srv = j.stats ? j.stats.elapsed_ms : '?';
    const rows = j.rows || [];
    S.evState.shown = rows.length;
    // SAUT OFFSET PROFOND (clic page lointaine, modèle Splunk) rendant 0 ligne ALORS que le total en promet
    // des données : budget interactif dépassé, PAS une vraie fin de données. Détecté ici, annoncé après le rendu
    // (le pager Préc/Suiv — curseur, fiable, illimité — reste affiché) au lieu d'une page vide muette et trompeuse.
    const heavyJump = keyset && jumpOff > 0 && rows.length === 0 && (S.evState.total < 0 || jumpOff < S.evState.total);
    if (keyset) {
      // KEYSET : le total vient du COUNT ASYNC (sans plafond) — NE PAS le remettre à -1 ici (il peut déjà être connu).
      // On mémorise le curseur de continuation (Suivant séquentiel rapide) ; le pager passe numéroté « X / N » dès
      // le total connu, avec saut à une page via OFFSET puis re-collage au curseur.
      S.evState.totalCapped = false;
      if (!S.evState.cursors) S.evState.cursors = [null];
      S.evState.cursors[S.evState.page + 1] = j.next_cursor || null;
    } else if (!S.evState.realTotal) {   // total inline (capé 10k) pour l'affichage IMMÉDIAT, tant que le COUNT async n'a pas donné le VRAI total
      S.evState.total = (typeof j.total === 'number') ? j.total : rows.length;
      S.evState.totalCapped = !!j.total_capped;   // COUNT borné serveur : plafonné -> le COUNT async le remplace par le vrai (| table inclus)
    }
    const eventable = ['ts', 'source', 'message'].every(c => (j.columns || []).includes(c));
    const forceTable = /\|\s*(table|fields|rex)\b/i.test(q) || !eventable;   // | table/fields/rex ou non-événementiel -> TABLE paginée (montre les colonnes extraites)
    S.evState.lastCols = j.columns; S.evState.lastRows = rows; S.evState.lastForceTable = forceTable;   // KEYSET : cache pour re-render du pager quand le COUNT async fixe le total
    if ($('#viz')) $('#viz').hidden = true;
    await new Promise(r => requestAnimationFrame(r));   // laisse le nav/clics respirer avant le build DOM lourd
    if (!S.exploreInflight || S.exploreInflight.qid !== qid) return;   // requête supersédée pendant le yield -> on jette ce rendu périmé
    if (forceTable) renderTablePaged($('#qresult'), j.columns, rows);
    else renderEvents($('#qresult'), j.columns, rows);
    renderQBadge(j.stats, { keyset, saut: jumpOff > 0, page: S.evState.page + 1 });
    showQExport(rows.length > 0);
    const net = Math.round(performance.now() - t0);
    if (keyset) {
      const kp = S.evState.total >= 0 ? Math.max(1, Math.ceil(S.evState.total / S.evState.pageSize)) : null;
      const ktot = S.evState.total >= 0 ? `${S.evState.total.toLocaleString('fr-FR')} résultats · ` : '';
      const kpg = kp ? `page ${S.evState.page + 1} / ${kp}` : `page ${S.evState.page + 1}${j.has_more ? ' · plus de résultats →' : ' · fin'}`;
      $('#qstats').textContent = `${ktot}${kpg} · serveur ${srv} ms · total ${net} ms`;
      if (heavyJump) $('#qstats').textContent = `${ktot}page ${S.evState.page + 1} lointaine trop lourde (budget dépassé) — utilise ◀ / ▶ pour un parcours fiable, ou affine la requête`;
      // P11.9-c — une page sautée servie PARTIELLE le dit dans la ligne d'état, pas seulement dans un badge.
      else if (jumpOff > 0 && j.stats && j.stats.truncated) $('#qstats').textContent = `${ktot}page ${S.evState.page + 1} atteinte par saut direct : contenu partiel (plafond serveur) — ◀ / ▶ parcourent le résultat complet par curseur`;
    } else {
      const pages = S.evState.total >= 0 ? Math.max(1, Math.ceil(S.evState.total / S.evState.pageSize)) : '?';
      // P11.13-f — CE LIBELLÉ NE PEUT PAS PASSER PAR LE LEXIQUE, IL EST DONC BILINGUE PAR CONSTRUCTION.
      // `i18nWalk` ne remplace que sur l'égalité du nœud texte ENTIER (web/i18n.js) ; or ce mot est un
      // FRAGMENT du nœud d'état (« page X/Y · … · serveur … ms · total … ms »), jamais un nœud à lui seul.
      // Une entrée au lexique serait une entrée MORTE — un vert sans traduction, le piège déjà nommé pour
      // les fragments de concaténation. Les trois autres états de `#qstats` (« Annulé », « exécution… »,
      // « Trop lourd… ») remplissent le nœud ENTIER : eux passent bien par le lexique.
      const totTxt = S.evState.total >= 0 ? (S.evState.total + (S.evState.totalCapped ? '+' : '') + ' lignes') : (LANG === 'en' ? 'unknown total' : 'total inconnu');
      $('#qstats').textContent = `page ${S.evState.page + 1}/${pages}${S.evState.totalCapped ? '+' : ''} · ${totTxt} · serveur ${srv} ms · total ${net} ms`;
    }
    if (S.evState.repriseAnnonce) {   // `P10.5-g` — la reprise se DIT : une page repartie de 1 sans un mot serait muette
      const cause = typeof S.evState.repriseAnnonce === 'string' ? ` (${S.evState.repriseAnnonce})` : '';
      $('#qstats').textContent = `parcours repris depuis la première page${cause} · ${$('#qstats').textContent}`;
      S.evState.repriseAnnonce = null;
    }
    // COUNT async SANS PLAFOND — keyset (total inconnu) OU offset CAPÉ (| table/| fields gardent l'offset + COUNT capé
    // à 10k) : récupère le VRAI total UNE fois -> pager numéroté COMPLET + « page X / N » réel, sans plafond qui cache des lignes.
    if (!S.evState.countFired && (keyset ? S.evState.total < 0 : S.evState.totalCapped)) {
      S.evState.countFired = true;
      const cq = q;
      // Le total doit compter la fenêtre que les PAGES parcourent, pas celle de l'instant où il part :
      // sinon le nombre de pages annoncé ne se rapporte à aucun parcours (`P10.5-g`).
      exploreCount(cq, isSoql, win.from, win.to).then(tot => {
        if (S.evState.q === cq && typeof tot === 'number' && tot >= 0) {
          S.evState.total = tot; S.evState.totalCapped = false; S.evState.realTotal = true;
          rerenderExplorePager();
          const pg = Math.max(1, Math.ceil(tot / S.evState.pageSize));
          $('#qstats').textContent = `${tot.toLocaleString('fr-FR')} résultats · page ${S.evState.page + 1} / ${pg}`;
        }
      });
    }
    $('#qstats').title = j.compiled_sql || '';
  } catch (e) {
    if (!S.exploreInflight || S.exploreInflight.qid !== qid) return;   // abort par STOP/supersession -> message déjà posé
    $('#qstats').textContent = explainErr(e);
  } finally {
    if (S.exploreInflight && S.exploreInflight.qid === qid) { S.exploreInflight = null; setRunning(false); }
  }
}

function qHistUpdateBtns() {
  const p = $('#qprev'), n = $('#qnext');
  if (p) p.disabled = S.qHistIdx <= 0;
  if (n) n.disabled = S.qHistIdx >= S.qHist.length - 1;
}

function qHistPush(sql) {
  try { recordRecentQuery(sql); } catch (e) {}   // historique récent client-only (localStorage) — capte TOUTE exécution (dédup + cap 20 en interne)
  if (S.qHistReplay) return;   // un rejeu (◀/▶) ne ré-empile pas
  const win = ($('#qrange') && $('#qrange').value) || '';
  const cur = S.qHist[S.qHistIdx];
  if (cur && cur.sql === sql && cur.win === win) return;   // pas de doublon de la position courante
  S.qHist = S.qHist.slice(0, S.qHistIdx + 1);   // nouvelle requête -> on coupe la branche « avant »
  S.qHist.push({ sql, win });
  if (S.qHist.length > 50) S.qHist.shift();   // borne mémoire
  S.qHistIdx = S.qHist.length - 1;
  qHistUpdateBtns();
}

function qHistGo(delta) {
  const ni = S.qHistIdx + delta;
  if (ni < 0 || ni >= S.qHist.length) return;
  S.qHistIdx = ni;
  const s = S.qHist[ni];
  S.qHistReplay = true;
  if ($('#sql')) $('#sql').value = s.sql;
  if ($('#qrange') && s.win) { $('#qrange').value = s.win; if (typeof updateQRangeBtn === 'function') updateQRangeBtn(); }
  runQuery();          // qHistPush() s'exécute en synchrone en tête de runQuery -> ignoré pendant le rejeu
  S.qHistReplay = false;
  qHistUpdateBtns();
}

async function runQuery() {
  const q = $('#sql').value.trim();
  if (!q) { cancelInflight(); $('#qresult').replaceChildren(); $('#qstats').textContent = ''; renderQBadge(null); showQExport(false); return; }
  const isSoql = /^\s*(search|metric)\b/i.test(q) || q.includes('|');
  // GARDE UI (#1c) — une saisie NON-GXQL part en {sql} BRUT (lecture arbitraire de toute
  // la base). Le SQL brut est RÉSERVÉ ADMIN : un non-admin garde tout son accès LECTURE via GXQL/search, on
  // refuse juste d'envoyer du SQL brut (la VRAIE garde reste serveur : /api/query renvoie 403). Message clair.
  if (!isSoql && !socIsAdmin()) {
    showQError('SQL brut réservé à l\'administrateur — utilisez GXQL (commencez par « search », ex : search source=… | stats count by …).');
    return;
  }
  qHistPush(q);   // ITEM 6 : empile la requête exécutée (sql + fenêtre) dans l'historique Explore
  // AGRÉGATION (stats/timechart/top/rare/eventstats) = résultat petit -> table/graphe, pas de pagination.
  // Tout le reste (raw, | table, | fields, | sort) PRÉSERVE les lignes -> pagination SERVEUR (scale 1M) via evLoad.
  const hasAgg = isSoql && /\|\s*(stats|timechart|top|rare|eventstats)\b/i.test(q);
  if (!hasAgg) {
    // KEYSET (#28) : `search` BRUT (sans pipe) -> curseur (ts,id) = parcours de la TOTALITÉ (auditd
    // 4M+/7j) sans plafond. Pipé -> OFFSET. Le motif « aucun pipe » est plus strict que ce que le daemon
    // sait faire (il sert le curseur sur `| table`/`| fields`/`| where`/`| sort -ts`) : l'élargir ici
    // changerait l'ORDRE des lignes affichées pour ces requêtes (l'offset les rend dans l'ordre physique
    // SQLite, non spécifié ; le curseur impose le plus récent d'abord), donc c'est une décision produit,
    // pas un simple alignement.
    const useKeyset = isSoql && q.indexOf('|') === -1;
    // `P10.5-g` — LA FENÊTRE D'UN PARCOURS EST GELÉE À SA CRÉATION, ET C'EST UNE CORRECTION, PAS UN
    // CONFORT. `exploreFrom()` rend `now - fenêtre`, RECALCULÉ à chaque appel : deux pages d'un même
    // parcours partaient donc sur deux fenêtres décalées de quelques secondes. Sur une fenêtre FROIDE,
    // le démon numérote les lignes par leur RANG dans l'ensemble hydraté : avancer la borne basse retire
    // des lignes du DÉBUT de cet ordre et décale TOUS les rangs — le curseur de la page précédente
    // désignait alors une AUTRE ligne, et la page suivante commençait ailleurs, en silence. Le démon
    // refuse désormais ce curseur (`cold_cursor_autre_numerotation`) au lieu de servir décalé ; ce qui
    // manquait ici, c'est de ne plus le lui présenter. Un parcours = une fenêtre, du début à la fin.
    S.evState = { q, isSoql, keyset: useKeyset, cursors: [null], page: 0, pageSize: evPageSize(), total: useKeyset ? -1 : 0, shown: 0, totalCapped: false, countFired: false, win: { from: exploreFrom(), to: exploreTo() } };
    await evLoad(); return;
  }
  // chemin agrégation : dédup / cancel-previous identique à evLoad (une seule requête explore en vol).
  const sig = exploreSig(q, isSoql, null, 0);
  if (S.exploreInflight && S.exploreInflight.sig === sig) return;   // dédup : agrégation identique déjà en vol -> on ignore le clic
  cancelInflight();
  const qid = nextQid(), ctrl = new AbortController();
  S.exploreInflight = { qid, sig, ctrl };
  setRunning(true); renderQBadge(null);
  const t0 = performance.now();
  $('#qstats').textContent = 'exécution…';
  try {
    const j = await runQ(q, isSoql, undefined, null, 0, { qid, signal: ctrl.signal, to: exploreTo() });   // idem : borne posée par la vue qui la règle
    if (!S.exploreInflight || S.exploreInflight.qid !== qid) return;   // supersédée -> on ignore le résultat périmé
    if (j.error) { showQError(j.error); return; }
    S.lastResult = { columns: j.columns, rows: j.rows };
    if ($('#viz')) $('#viz').hidden = false;
    renderViz();
    renderQBadge(j.stats);
    showQExport((j.rows || []).length > 0);
    const net = Math.round(performance.now() - t0);
    $('#qstats').textContent = `${j.stats.rows} ligne(s)${j.stats.truncated ? ' (tronqué — affine la requête)' : ''} - serveur ${j.stats.elapsed_ms} ms - total ${net} ms${j.compiled_sql ? ' - GXQL' : ''}`;
    $('#qstats').title = j.compiled_sql || '';
  } catch (e) {
    if (!S.exploreInflight || S.exploreInflight.qid !== qid) return;
    $('#qstats').textContent = explainErr(e);
  } finally {
    if (S.exploreInflight && S.exploreInflight.qid === qid) { S.exploreInflight = null; setRunning(false); }
  }
}

// EXPORT Explore (CSV/JSON = jeu complet borné via /api/export ; PDF = impression de la surface #query).
function showQExport(has) { const el = $('#qexport'); if (el) el.hidden = !has; }


export { banIp, clearDrillCrumb, clearZoom, coverageBadge, coverageHorizonNodes, provenanceBadge, currentFrom, currentTo, evLoad, exploreFrom, exploreTo, noeudsDeVizReglee, qHistGo, queryCount, refusDeReglage, reglageLu, renderViz, runQ, runQuery, setZoom, sondage, stopExplore, tableEl, updateZoomBadge, vizElement, vizSansPorte, refusDeRepresentation, truncationBadge };

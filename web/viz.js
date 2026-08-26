// viz.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Explore + viz/charts: drilldown, fenetre glissante, requete interactive, rendu table/graphes (partages avec dashboards).
import { $, CSSV, LANG, LOC, SEV, api, apiSend, colComparator, confirmModal, esc, flashStopped, fmtTs, ic, makePager, muted, sev, socIsAdmin, toast, tzOpts } from './core.js';
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

function vizElement(mode, cols, rows, query, drill) {
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
// CE QUE CE BLOC NE FAIT PAS, écrit plutôt que tu : il ne redresse PAS le chemin PAR DÉFAUT. Mesuré
// le même jour sur banc, sans aucun réglage : `gauge` sur une colonne textuelle affiche « 0 / 1 » (un
// zéro FABRIQUÉ), `line` écrase toutes les abscisses non numériques sur un point unique, `bar` trace
// toutes ses barres à 0 % de large tout en imprimant le texte à côté, et `pie` répond « aucune
// donnée » alors que les lignes existent — une ABSENCE affirmée à la place d'un refus. Seul
// `histogram` dit « aucune donnée numérique ». Les redresser changerait ce que rendent des panneaux
// existants, ce que la borne de ce chantier interdit ; le refus ci-dessous est donc attaché au CHOIX.
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
function rendreEnSonde(mode, rows) { try { return vizElement(mode, SONDE_COLS, rows, '', ''); } catch (e) { return null; } }
const _sondages = new Map();
function sondage(mode) {
  if (_sondages.has(mode)) return _sondages.get(mode);
  const geo = rows => marquesDe(rendreEnSonde(mode, rows)).join(';');
  const trace = geo(SONDE_N1) !== geo(SONDE_N2);               // TÉMOIN POSITIF : la géométrie suit la valeur
  const ordonneeNumerique = trace && geo(SONDE_T1) === geo(SONDE_T2);
  const ref = empreinteDe(rendreEnSonde(mode, SONDE_N1));
  const fentes = SONDE_COLS.map((_, k) => {
    const mut = SONDE_N1.map(r => r.map((v, j) => (j === k ? Number(v) + 500 : v)));
    return empreinteDe(rendreEnSonde(mode, mut)) !== ref;
  });
  const s = { trace, ordonneeNumerique, fentes };
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
function profilsDeColonnes(cols, rows) {
  return cols.map((nom, i) => {
    let nonVides = 0, nombres = 0; const vus = new Set();
    for (const r of rows) {
      const v = r[i];
      if (v === null || v === undefined || v === '') continue;
      nonVides++;
      if (Number.isFinite(Number(v))) nombres++;
      vus.add(String(v));
    }
    return { nom, i, nonVides, nombres, cardinalite: vus.size, numerique: nonVides > 0 && nombres === nonVides };
  });
}
function premiereNonNumerique(rows, i) {
  for (const r of rows) { const v = r[i]; if (v !== null && v !== undefined && v !== '' && !Number.isFinite(Number(v))) return String(v).slice(0, 40); }
  return '';
}

// -- UN CHOIX IMPOSSIBLE PRODUIT UN REFUS QUI DIT POURQUOI --------------------------------------
// Trois causes, toutes DÉRIVÉES — de ce que la requête rend, et de ce que la représentation a répondu
// au sondage. Aucune ne cite un type de graphe. Le refus prend la place du GRAPHE, jamais celle des
// données : il n'est décidé dans aucun test qui jugerait aussi un vide, et il nomme la colonne, le
// compte et la valeur qui le motivent.
function refusDeReglage(mode, cols, rows, reglage) {
  const s = sondage(mode), profils = profilsDeColonnes(cols, rows);
  const parNom = nom => profils.find(p => p.nom === nom) || null;
  for (const nom of [reglage.x, reglage.s, reglage.y]) {
    if (nom && !parNom(nom)) return {
      fr: 'colonne « ' + nom + ' » absente du résultat, qui ne rend plus que ' + cols.join(', ') + '. Choisis une autre colonne.',
      en: 'column “' + nom + '” is not in the result, which now returns only ' + cols.join(', ') + '. Pick another column.',
    };
  }
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
// Les fentes NON choisies gardent ce que la règle positionnelle leur donnait : première colonne en
// abscisse, dernière en ordonnée, deuxième en 2e dimension là où la représentation la lit. Régler UN
// axe ne déplace donc pas l'autre.
function projeter(mode, cols, rows, reglage) {
  const s = sondage(mode);
  const rang = nom => cols.indexOf(nom);
  const ix = reglage.x ? rang(reglage.x) : 0;
  const iy = reglage.y ? rang(reglage.y) : cols.length - 1;
  const is = reglage.s ? rang(reglage.s) : ((s.fentes[1] && cols.length >= 3) ? 1 : -1);
  const ordre = [ix]; if (is >= 0) ordre.push(is); ordre.push(iy);
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
  s.value = (choix && colonnes.some(p => p.nom === choix)) ? choix : '';
  s.onchange = () => onChoix(s.value || '');
  l.append(libelle, s);
  return l;
}
function barreDeReglage(mode, cols, rows, reglage, onChoix) {
  const s = sondage(mode), profils = profilsDeColonnes(cols, rows);
  const barre = document.createElement('div');
  barre.className = 'rf-row';
  if (s.fentes[0]) barre.appendChild(selecteurDeFente(
    LANG === 'en' ? 'X axis ' : 'Abscisse ',
    LANG === 'en' ? 'Column handed to the chart in first position' : 'Colonne remise au graphe en première position',
    profils, reglage.x, v => onChoix(Object.assign({}, reglage, { x: v }))));
  if (s.fentes[1]) barre.appendChild(selecteurDeFente(
    LANG === 'en' ? '2nd dimension ' : '2e dimension ',
    LANG === 'en' ? 'Column handed to the chart in middle position' : 'Colonne remise au graphe en position médiane',
    profils, reglage.s, v => onChoix(Object.assign({}, reglage, { s: v }))));
  barre.appendChild(selecteurDeFente(
    LANG === 'en' ? 'Y axis ' : 'Ordonnée ',
    LANG === 'en' ? 'Column handed to the chart in last position' : 'Colonne remise au graphe en dernière position',
    profils, reglage.y, v => onChoix(Object.assign({}, reglage, { y: v }))));
  return barre;
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
  if (sondage(mode).trace && cols.length >= 2) out.push(barreDeReglage(mode, cols, rows, reglage, r => { reglageEcrit(cle, r); redessiner(); }));
  if (!regle) { out.push(vizElement(mode, cols, rows, query, drill)); return out; }
  const refus = refusDeReglage(mode, cols, rows, reglage);
  if (refus) {
    const d = document.createElement('div');
    d.className = 'rf-hint bad';
    d.textContent = (LANG === 'en' ? 'Chart refused — ' : 'Graphe refusé — ') + (LANG === 'en' ? refus.en : refus.fr);
    out.push(d);
    return out;
  }
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

// GAUGE — une seule valeur (comme stat) rendue en arc (jauge 270°). Max déduit : name='cpu_pct'/%→100,
// sinon la valeur elle-même sert d'échelle (pleine). Clic -> drill (comme stat).
function gaugeEl(cols, rows, query, drill) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const key = unitKeyFor(cols, query);
  const raw = rows.length ? Number(rows[0][rows[0].length - 1]) : 0;
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
  return svg;
}

// PIE / DONUT — catégorie + valeur ([label, count]). Secteurs SVG proportionnels + légende. Clic secteur -> drill.
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
  data.slice(0, 12).forEach((d, i) => {
    const row = document.createElement('div'); row.className = 'pielg';
    const sw = document.createElement('span'); sw.className = 'pieswatch'; sw.style.background = catColor(i);
    const lb = document.createElement('span'); lb.className = 'pielabel'; lb.textContent = d.label;
    const vc = document.createElement('span'); vc.className = 'pieval'; vc.textContent = d.v;
    row.append(sw, lb, vc); legend.appendChild(row);
  });
  wrap.append(svg, legend);
  return wrap;
}

// HEATMAP — deux dimensions + valeur ([ligne, colonne, valeur], ex `stats count by host, source`). Grille de
// cellules, intensité = valeur normalisée. Repli 2 colonnes -> heatmap 1×N (dégradé sur la seule dimension).
function heatmapEl(cols, rows, query, drill) {
  const has2 = cols.length >= 3;
  const ri = 0, ci = has2 ? 1 : 0, vi = cols.length - 1;
  const rowKeys = [], colKeys = [], rowSeen = new Set(), colSeen = new Set();
  const cell = new Map(); // "r\x1fc" -> value  (\x1f = unit separator : jamais present dans une valeur de dimension)
  rows.forEach(r => {
    const rk = r[ri] == null ? '-' : String(r[ri]);
    const ck = has2 ? (r[ci] == null ? '-' : String(r[ci])) : 'valeur';
    if (!rowSeen.has(rk)) { rowSeen.add(rk); rowKeys.push(rk); }
    if (!colSeen.has(ck)) { colSeen.add(ck); colKeys.push(ck); }
    cell.set(rk + '\x1f' + ck, Number(r[vi]) || 0);
  });
  const max = Math.max(1, ...[...cell.values()]);
  const wrap = document.createElement('div'); wrap.className = 'heatwrap';
  const tbl = document.createElement('table'); tbl.className = 'heatmap';
  const thead = document.createElement('thead'); const htr = document.createElement('tr');
  htr.appendChild(document.createElement('th'));
  colKeys.slice(0, 40).forEach(ck => { const th = document.createElement('th'); th.textContent = ck; th.title = ck; htr.appendChild(th); });
  thead.appendChild(htr); tbl.appendChild(thead);
  const tb = document.createElement('tbody');
  rowKeys.slice(0, 60).forEach(rk => {
    const tr = document.createElement('tr');
    const rh = document.createElement('th'); rh.className = 'heatrow'; rh.textContent = rk; rh.title = rk; tr.appendChild(rh);
    colKeys.slice(0, 40).forEach(ck => {
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
  return wrap;
}

// HISTOGRAM — distribution binned d'une colonne numérique. Si les lignes portent DÉJÀ [bucket,count]
// (agrégat) on les rend en barres contiguës ; sinon on binne la dernière colonne numérique (Sturges borné).
function histogramEl(cols, rows, query, drill) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const vi = cols.length - 1;
  const vals = rows.map(r => Number(r[vi])).filter(n => Number.isFinite(n));
  const wrap = document.createElement('div'); wrap.className = 'histwrap';
  if (!vals.length) { wrap.appendChild(muted('aucune donnée numérique')); return wrap; }
  let bins;
  if (rows.length > 1 && cols.length >= 2) {
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
    menu.style.top = (r.bottom + 4) + 'px'; menu.style.right = (window.innerWidth - r.right) + 'px';
    document.body.appendChild(menu);
    const onclose = e => { if (!menu.contains(e.target) && e.target !== colsBtn) closeColsMenu(); };
    const onscroll = () => closeColsMenu();
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
  return d;
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
    const opts = { qid, signal: ctrl.signal, to: exploreTo() };   // `P11.18-r` : l'Explore RÈGLE cet intervalle et l'AFFICHE (#zoombadge) — il le passe, il ne l'hérite pas.
    if (keyset) { opts.keyset = true; if (cursor) opts.cursor = cursor; else if (jumpOff) opts.offset = jumpOff; }   // curseur (séquentiel) OU offset (saut) ; sinon 1re page
    const j = await runQ(q, isSoql, undefined, limit, offset, opts);
    if (!S.exploreInflight || S.exploreInflight.qid !== qid) return;   // supersédée (autre requête lancée) -> on ignore le résultat périmé
    if (j.error) { showQError(j.error); return; }
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
    // COUNT async SANS PLAFOND — keyset (total inconnu) OU offset CAPÉ (| table/| fields gardent l'offset + COUNT capé
    // à 10k) : récupère le VRAI total UNE fois -> pager numéroté COMPLET + « page X / N » réel, sans plafond qui cache des lignes.
    if (!S.evState.countFired && (keyset ? S.evState.total < 0 : S.evState.totalCapped)) {
      S.evState.countFired = true;
      const cq = q;
      exploreCount(cq, isSoql, exploreFrom(), exploreTo()).then(tot => {
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
    S.evState = { q, isSoql, keyset: useKeyset, cursors: [null], page: 0, pageSize: evPageSize(), total: useKeyset ? -1 : 0, shown: 0, totalCapped: false, countFired: false };
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


export { banIp, clearDrillCrumb, clearZoom, currentFrom, currentTo, evLoad, exploreFrom, exploreTo, noeudsDeVizReglee, qHistGo, queryCount, refusDeReglage, reglageLu, renderViz, runQ, runQuery, setZoom, sondage, stopExplore, tableEl, updateZoomBadge, vizElement, truncationBadge };

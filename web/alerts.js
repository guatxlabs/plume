// alerts.js — file d'alertes : rendu, triage groupe, drill, export, filtres MITRE/source
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, esc, sev, fmtTs, ic, withBusy, api, apiSend, makePager, exportBar, confirmModal, mitreName } from './core.js';
import { S } from './state.js';
import { banIp, runQuery, updateZoomBadge } from './viz.js';
import { canEditCases, addToCase, openCase } from './cases.js';
import { refresh, updateRangeBtn } from './app.js';

// clic sur une alerte -> ouvre l'explore sur les ÉVÉNEMENTS déclencheurs. Le `detail` de l'alerte
// = la requête de la règle (ex "search severity>=3 | stats count") -> on garde la tête `search`
// (sans le | stats/timechart) pour voir les events. Sinon (alerte collecteur) : IP du titre, ou le titre.
function alertDrill(a) {
  if (!a) return;
  let q = (a.detail || '').trim();
  if (/^\s*(search|metric)\b/i.test(q)) {
    q = q.split('|')[0].trim();                 // enlève la transformation -> les événements bruts
  } else {
    const ipm = ((a.title || '') + ' ' + (a.detail || '')).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    q = ipm ? ('search src_ip:' + ipm[0]) : ('search ' + (a.title || '').split(':')[0].trim());
  }
  // FENÊTRE : on centre l'Explore sur la fenêtre d'ÉVALUATION de l'alerte (et non sur la fenêtre 24h
  // glissante) -> from = ts - window_s, to = ts (+ petite marge pour voir l'événement de bord). On passe
  // par zoomRange{from,to} qui est PRIORITAIRE dans exploreFrom/exploreTo. ts peut manquer (vieille alerte) :
  // on retombe alors sur la fenêtre glissante (comportement historique).
  if (a.ts) {
    const w = (a.window_s || 3600);
    const margin = Math.min(600, Math.max(30, Math.round(w * 0.05)));
    S.zoomRange = { from: Math.floor(a.ts - w - margin), to: Math.ceil(a.ts + margin) };
    updateZoomBadge(); if (typeof updateRangeBtn === 'function') updateRangeBtn();
  }
  location.hash = 'explore';
  if ($('#sql')) { $('#sql').value = q; runQuery(); }
}
// PURPLE — filtre actif sur les alertes par technique MITRE (pivot depuis le panneau couverture ou un
// chip d'alerte). '' = aucun filtre (toutes les alertes). Cf. ?mitre= côté daemon (index idx_alert_mitre).
/* state: alertMitreFilter -> S (state.js) */
// BATCH 1 : la vue MITRE « tous statuts » (historique de détection, potentiellement grande) est PAGINÉE
// côté serveur (LIMIT/OFFSET + total). Page courante remise à 0 dès qu'un filtre change.
const ALERT_HIST_PS = 50;
/* state: alertHistPage -> S (state.js) */
// TRIAGE GROUPÉ (« 1 groupe = N occurrences ») — rend la file gérable au volume (10^4/j). Axe de
// regroupement de la file d'alertes : '' = vue PLATE (backlog classique, comportement historique inchangé) ;
// 'rule'|'host'|'mitre' = liste de GROUPES paginée serveur (/api/alerts/groups), chaque groupe REPLIABLE et
// expansé à la demande (occurrences paginées via le chemin plat gkey/gval). N'affecte QUE la file par défaut
// (jamais les drills mitre/source). alertGroupAll : groupes des alertes ACTIVES (status=new) vs TOUS statuts.
/* state: alertGroupBy -> S (state.js) */
/* state: alertGroupAll -> S (state.js) */
/* state: alertGroupPage -> S (state.js) */
const ALERT_GROUP_PS = 25;   // groupes par page
const ALERT_OCC_PS = 25;     // occurrences par page dans un groupe déplié
function setAlertGroupBy(g) { S.alertGroupBy = alert_group_axis(g) ? g : ''; S.alertGroupPage = 0; location.hash = 'alerts'; renderAlerts(true); }
function alert_group_axis(g) { return g === 'rule' || g === 'host' || g === 'mitre'; }
// le pivot MITRE amène vers Investigation -> Alertes (onglet #alerts, où vivent les Alertes actives, cf. SPACES).
function setAlertMitreFilter(m) { S.alertMitreFilter = (m || '').trim().toUpperCase(); S.alertSourceFilter = ''; S.alertHistPage = 0; location.hash = 'alerts'; renderAlerts(true); }
// FIX 2 — filtre actif sur les alertes par SOURCE (pivot depuis la cloche d'un feed « chaud » de la
// fraîcheur). '' = aucun filtre. Il n'existe PAS de filtre source côté serveur : on récupère les alertes
// 'new' et on les filtre CÔTÉ CLIENT sur les jetons `source=<x>` de leur `detail` (la requête de la règle),
// exactement comme extract_query_sources côté daemon le fait pour le compteur active_alerts du feed.
/* state: alertSourceFilter -> S (state.js) */
function alertSources(detail) {
  const out = [], re = /source\s*=\s*(?:'([^']*)'|"([^"]*)"|([^\s|'"]+))/g; let m;
  while ((m = re.exec(detail || ''))) out.push(m[1] || m[2] || m[3]);
  return out;
}
function setAlertSourceFilter(src) { S.alertSourceFilter = (src || '').trim(); S.alertMitreFilter = ''; S.alertHistPage = 0; location.hash = 'alerts'; renderAlerts(true); }
// « voir les events » d'une technique sans alerte : recherche plein-texte du tag MITRE (best-effort, les
// events ne portent pas toujours de champ mitre) -> l'analyste investigue depuis l'Explore.
function mitreEventsDrill(m) {
  m = (m || '').trim(); if (!m) return;
  location.hash = 'explore';
  if ($('#sql')) { $('#sql').value = 'search ' + m; runQuery(); }
}
const ALERT_IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
// TEMPLATE d'une ligne d'alerte — PARTAGÉ entre la vue plate et les occurrences d'un groupe déplié. `i` =
// index dans le tableau passé à wireAlertRows (drill). Reprend TEL QUEL les conventions existantes
// (.alert/.sev/.mitrechip.mitrepivot/.casechip/.casebtn/.banbtn/.ackdone) -> zéro divergence de rendu.
function alertRowHtml(a, i) {
  const ipm = ((a.title || '') + ' ' + (a.detail || '')).match(ALERT_IP_RE);
  const ban = ipm ? `<button class="banbtn" data-ip="${esc(ipm[0])}" title="Bannir ${esc(ipm[0])} (action en attente, dry-run)">${ic('ban')}</button>` : '';
  const cas = a.case_id
    ? `<button class="casechip" data-cid="${a.case_id}" title="Rattachée au case #${a.case_id} - cliquer pour ouvrir">${ic('case')} #${a.case_id}</button>`
    : (canEditCases() ? `<button class="casebtn" data-t="${esc(a.title)}" data-d="${esc(a.detail || '')}" data-id="${a.id}" title="Ajouter à un case">${ic('case')}</button>` : '');
  const mt = a.mitre ? ` <span class="mitrechip mitrepivot" data-m="${esc(a.mitre)}" title="${esc(a.mitre)}${mitreName(a.mitre) ? ' — ' + esc(mitreName(a.mitre)) : ''} · filtrer les alertes par cette technique (MITRE ATT&CK, héritée de la règle)">${esc(a.mitre)}</span>` : '';
  return `
    <div class="alert sev-${a.severity}">
      <span class="sev">${sev(a.severity)}</span>
      <span class="title"><span class="alertdrill" data-idx="${i}" title="Cliquer → voir les événements déclencheurs">${esc(a.title)}</span>${mt}</span>
      <time>${fmtTs(a.ts)}</time>
      <span class="alertact">${cas}${ban}${a.status === 'new' ? `<button data-ack="${a.id}" title="Acquitter : marquer comme vue (retire de la file active, sans la supprimer)">Acquitter</button>` : `<span class="ackdone" title="Acquittée${a.acked_at ? ' · ' + fmtTs(a.acked_at) : ''}${a.acked_by ? ' par ' + esc(a.acked_by) : ''}">${ic('check')} Acquittée</span>`}</span>
    </div>`;
}
// WIRING partagé des lignes d'alerte présentes dans `host` pour le tableau `alerts` (index-aligné avec
// data-idx). `afterAck` = callback exécuté après un acquittement (vue plate: renderAlerts/refresh ; groupe:
// recharge les occurrences du groupe). Les sélecteurs sont SCOPÉS à `host` -> deux groupes dépliés ne se
// marchent pas dessus.
function wireAlertRows(host, alerts, afterAck) {
  host.querySelectorAll('.mitrepivot').forEach(el => el.onclick = (e) => { e.stopPropagation(); setAlertMitreFilter(el.dataset.m); });
  host.querySelectorAll('[data-ack]').forEach(btn => btn.onclick = () => withBusy(btn, async () => {
    await apiSend('/alerts/' + btn.dataset.ack + '/ack');
    await afterAck();
  }));
  host.querySelectorAll('.banbtn').forEach(btn => btn.onclick = () => banIp(btn.dataset.ip));
  host.querySelectorAll('.alertdrill').forEach(el => el.onclick = () => { el.classList.add('drilling'); setTimeout(() => el.classList.remove('drilling'), 1200); alertDrill(alerts[Number(el.dataset.idx)]); });
  host.querySelectorAll('.casebtn').forEach(btn => btn.onclick = () => withBusy(btn, () => addToCase('alert', btn.dataset.t + (btn.dataset.d ? ' - ' + btn.dataset.d : ''), 'alert:' + btn.dataset.id)));
  host.querySelectorAll('.casechip').forEach(btn => btn.onclick = () => withBusy(btn, () => openCase(Number(btn.dataset.cid))));
}
// Toggle de vue (segmenté) : Plate / par Règle / par Hôte / par Technique. Affiché uniquement sur la file par
// défaut et la vue groupée (pas dans un drill mitre/source). `active` = axe courant ('' = plate).
function alertViewControls(active) {
  const opt = (g, label, title) => `<button type="button" class="agseg${active === g ? ' on' : ''}" data-g="${g}" title="${esc(title)}">${label}</button>`;
  return `<div class="alertview" role="group" aria-label="Vue des alertes"><span class="muted">Vue</span>`
    + opt('', 'Plate', 'Liste plate (backlog à traiter)')
    + opt('rule', 'Règle', 'Grouper par règle — 1 groupe = N occurrences (triage au volume)')
    + opt('host', 'Hôte', 'Grouper par hôte / entité')
    + opt('mitre', 'Technique', 'Grouper par technique MITRE ATT&CK')
    + `</div>`;
}
function wireAlertViewControls(host) {
  host.querySelectorAll('.agseg').forEach(btn => btn.onclick = () => setAlertGroupBy(btn.dataset.g));
}

// EXPORT ALERTES (client) : sérialise les alertes DÉJÀ chargées (vue courante / page). Aucune colonne
// secrète (le schéma alert = id/ts/rule/severity/title/status/detail/mitre/case_id/acked_*). ts en clair.
const ALERT_EXPORT_COLS = [
  { key: 'id', label: 'id' }, { key: 'ts', label: 'ts' }, { key: 'severity', label: 'severity' },
  { key: 'title', label: 'title' }, { key: 'status', label: 'status' }, { key: 'rule', label: 'rule' },
  { key: 'mitre', label: 'mitre' }, { key: 'case_id', label: 'case_id' }, { key: 'detail', label: 'detail' },
  { key: 'acked_at', label: 'acked_at' }, { key: 'acked_by', label: 'acked_by' },
];
function alertExportRow(a) {
  return {
    id: a.id, ts: fmtTs(a.ts), severity: sev(a.severity), title: a.title || '', status: a.status || '',
    rule: a.rule || '', mitre: a.mitre || '', case_id: a.case_id || '', detail: a.detail || '',
    acked_at: a.acked_at ? fmtTs(a.acked_at) : '', acked_by: a.acked_by || '',
  };
}
function alertsExportBar(alerts, total) {
  // `total` connu (vue MITRE paginée) et > page affichée -> prévenir que l'export ne porte que la page courante.
  const opts = (typeof total === 'number' && total > alerts.length) ? { partial: { shown: alerts.length, total } } : undefined;
  return exportBar('alertes', () => ({ cols: ALERT_EXPORT_COLS, rows: alerts.map(alertExportRow) }), 'alerts', opts);
}
// EXPORT GROUPES d'alertes (« 1 groupe = N occurrences ») : le résumé des groupes affichés (déjà chargés).
const ALERT_GROUP_EXPORT_COLS = [
  { key: 'key', label: 'key' }, { key: 'count', label: 'count' }, { key: 'open', label: 'open' },
  { key: 'severity', label: 'severity' }, { key: 'sample', label: 'sample' }, { key: 'mitre', label: 'mitre' },
  { key: 'last_ts', label: 'last_ts' },
];
function alertGroupExportRow(g) {
  return { key: g.gkey || '', count: g.n, open: g.open_n || 0, severity: sev(g.severity), sample: g.sample_title || '', mitre: g.mitre || '', last_ts: g.last_ts ? fmtTs(g.last_ts) : '' };
}
function alertGroupsExportBar(groups, total) {
  // `total` = nb de groupes serveur ; > page affichée -> export = page courante de groupes uniquement.
  const opts = (typeof total === 'number' && total > groups.length) ? { partial: { shown: groups.length, total } } : undefined;
  return exportBar('alertes-groupes', () => ({ cols: ALERT_GROUP_EXPORT_COLS, rows: groups.map(alertGroupExportRow) }), 'alerts', opts);
}

async function renderAlerts(loading) {
  // TRIAGE GROUPÉ : la file PAR DÉFAUT peut basculer en vue de GROUPES repliables (jamais en drill mitre/source).
  if (S.alertGroupBy && !S.alertMitreFilter && !S.alertSourceFilter) return renderAlertGroups(loading);
  // Sans filtre : alertes ACTIVES non acquittées ET sans case (status=new&uncased=1) -> backlog = à traiter.
  // Avec filtre technique : on veut TOUS les statuts (status=all) -> on montre l'historique de détection de
  // la technique, pas seulement l'actif (sinon « aucune alerte » trompeur alors qu'il y a des détections
  // passées). Cf. ?mitre=&status=&uncased= côté daemon.
  // URL : MITRE (tous statuts) > SOURCE (alertes 'new', filtrées côté client) > défaut (backlog new+uncased).
  // BATCH 1 : la branche MITRE (status=all) est PAGINÉE serveur (limit/offset) ; les autres branches (backlog
  // 'new', bornées) restent inchangées.
  const url = S.alertMitreFilter
    ? '/alerts?status=all&mitre=' + encodeURIComponent(S.alertMitreFilter) + '&limit=' + ALERT_HIST_PS + '&offset=' + (S.alertHistPage * ALERT_HIST_PS)
    : S.alertSourceFilter
      ? '/alerts?status=new'
      : '/alerts?status=new&uncased=1';
  const b = $('#alerts .body'); if (!b) return;
  if (loading) { let prog = b.querySelector(':scope > .tableprog'); if (!prog) { prog = document.createElement('div'); prog.className='tableprog'; b.insertBefore(prog, b.firstChild); } prog.hidden=false; b.classList.add('reloading'); }
  let alerts, alertTotal;
  try { const resp = await api(url); alerts = resp.alerts || []; alertTotal = resp.total; } catch (e) { b.classList.remove('reloading'); b.innerHTML = '<div class="bad">alertes indisponibles : ' + esc(e.message) + '</div>'; return; }
  b.classList.remove('reloading');
  // filtre SOURCE (pas de filtre serveur) : on ne garde que les alertes dont la règle vise cette source.
  if (S.alertSourceFilter && !S.alertMitreFilter) alerts = alerts.filter(a => alertSources(a.detail).includes(S.alertSourceFilter));
  // Le toggle de vue n'apparaît QUE sur la file par défaut (pas dans un drill mitre/source).
  const viewControls = (!S.alertMitreFilter && !S.alertSourceFilter) ? alertViewControls('') : '';
  // bandeau retirable quand un filtre (technique MITRE ou source) est actif
  const filterBar = S.alertMitreFilter
    ? `<div class="mitrefilter">Filtre MITRE : <span class="mitrechip">${esc(S.alertMitreFilter)}</span> <span class="muted">(tous statuts)</span><button id="mitre-clear" type="button" title="Retirer le filtre">${ic('x')}</button></div>`
    : S.alertSourceFilter
      ? `<div class="mitrefilter">Source : <span class="mitrechip">${esc(S.alertSourceFilter)}</span> <span class="muted">(alertes actives)</span><button id="src-clear" type="button" title="Retirer le filtre">${ic('x')}</button></div>`
      : '';
  if (!alerts.length) {
    if (S.alertMitreFilter) {
      // 0 alerte même TOUS statuts -> on propose de voir les events de la technique (pas de cul-de-sac)
      b.innerHTML = filterBar + `<div class="muted">Aucune alerte (tous statuts) pour cette technique. <button id="mitre-events" type="button" class="linklike">Voir les events ${esc(S.alertMitreFilter)}</button></div>`;
      const ev = b.querySelector('#mitre-events'); if (ev) ev.onclick = () => mitreEventsDrill(S.alertMitreFilter);
    } else if (S.alertSourceFilter) {
      b.innerHTML = filterBar + `<div class="muted">Aucune alerte active pour la source <b>${esc(S.alertSourceFilter)}</b>.</div>`;
    } else {
      b.innerHTML = viewControls + '<div class="ok">Aucune alerte active </div>';
    }
    const c = b.querySelector('#mitre-clear'); if (c) c.onclick = () => setAlertMitreFilter('');
    const sc = b.querySelector('#src-clear'); if (sc) sc.onclick = () => setAlertSourceFilter('');
    wireAlertViewControls(b);
    return;
  }
  // filtré (MITRE tous statuts, ou source) : libellé neutre + pas de « Tout acquitter » (ack-all est GLOBAL,
  // pas restreint au filtre). Non filtré : file active classique avec ack-all.
  // vue MITRE paginée : le compteur reflète le TOTAL (pas la page) ; le pager montre la fenêtre.
  const mitreCount = (S.alertMitreFilter && typeof alertTotal === 'number') ? alertTotal : alerts.length;
  const head = (S.alertMitreFilter || S.alertSourceFilter)
    ? `<div class="alerthead"><span>${mitreCount} alerte(s)${S.alertMitreFilter ? ' — tous statuts' : ' — source ' + esc(S.alertSourceFilter)}</span></div>`
    : `<div class="alerthead"><span>${alerts.length} alerte(s) active(s)</span><button id="ack-all" type="button" title="Acquitter toutes les alertes actives">${ic('check')} Tout acquitter</button></div>`;
  b.innerHTML = viewControls + filterBar + head + alerts.map((a, i) => alertRowHtml(a, i)).join('');
  const clr = b.querySelector('#mitre-clear'); if (clr) clr.onclick = () => setAlertMitreFilter('');
  const sclr = b.querySelector('#src-clear'); if (sclr) sclr.onclick = () => setAlertSourceFilter('');
  wireAlertViewControls(b);
  const ackAll = b.querySelector('#ack-all');
  if (ackAll) ackAll.onclick = () => withBusy(ackAll, async () => {
    if (!await confirmModal(`Acquitter les ${alerts.length} alerte(s) active(s) ?`, { okText: 'Acquitter', danger: false })) return;
    await apiSend('/alerts/ack-all');
    await refresh();
  });
  // WIRING des lignes (drill/ack/ban/case) : ack -> re-render filtré, ou refresh global (comportement historique).
  wireAlertRows(b, alerts, () => (S.alertMitreFilter || S.alertSourceFilter) ? renderAlerts() : refresh());
  // EXPORT : barre CSV/JSON/PDF dans l'en-tête (sur les alertes de la vue courante, déjà chargées).
  { const ah = b.querySelector('.alerthead'); if (ah && alerts.length) ah.appendChild(alertsExportBar(alerts, S.alertMitreFilter ? alertTotal : undefined)); }
  // BATCH 1 : pager (haut+bas) sur la vue MITRE tous-statuts (serveur limit/offset) ; auto-caché si <=1 page.
  if (S.alertMitreFilter && typeof alertTotal === 'number') {
    const pgState = { page: S.alertHistPage, pageSize: ALERT_HIST_PS, total: alertTotal, shown: alerts.length };
    const go = p => { S.alertHistPage = p; renderAlerts(true); };
    const top = makePager(pgState, go), bot = makePager(pgState, go);
    const firstAlert = b.querySelector('.alert');
    if (top && firstAlert) b.insertBefore(top, firstAlert);
    if (bot) b.appendChild(bot);
  }
}

// TRIAGE GROUPÉ — vue de GROUPES repliables (« 1 groupe = N occurrences »). Groupes paginés serveur
// (/api/alerts/groups) ; chaque groupe déplié charge ses occurrences à la demande (chemin plat gkey/gval,
// paginé). Le scope (actives vs tous statuts) s'applique À LA FOIS au groupement et à l'expansion -> le
// compteur `n` du groupe et le `total` des occurrences restent COHÉRENTS.
async function renderAlertGroups(loading) {
  const b = $('#alerts .body'); if (!b) return;
  const scope = S.alertGroupAll ? 'all' : 'new';
  // ui-regression — le scope « Actives » = status=new ET NON ENCAISSÉ (uncased), pour réconcilier
  // avec le badge de posture (overview) et la vue plate (backlog new+uncased). Sans uncased, des alertes déjà en
  // case réapparaissaient dans la file active groupée. Scope « Tous statuts » : pas de filtre uncased (inchangé).
  const url = '/alerts/groups?group=' + encodeURIComponent(S.alertGroupBy) + '&status=' + scope
            + (S.alertGroupAll ? '' : '&uncased=1')
            + '&limit=' + ALERT_GROUP_PS + '&offset=' + (S.alertGroupPage * ALERT_GROUP_PS);
  if (loading) { let prog = b.querySelector(':scope > .tableprog'); if (!prog) { prog = document.createElement('div'); prog.className='tableprog'; b.insertBefore(prog, b.firstChild); } prog.hidden=false; b.classList.add('reloading'); }
  let groups, total;
  try { const r = await api(url); groups = r.groups || []; total = r.total; }
  catch (e) { b.classList.remove('reloading'); b.innerHTML = alertViewControls(S.alertGroupBy) + '<div class="bad">groupes indisponibles : ' + esc(e.message) + '</div>'; wireAlertViewControls(b); return; }
  b.classList.remove('reloading');
  const axisLabel = { rule: 'règle', host: 'hôte', mitre: 'technique' }[S.alertGroupBy] || S.alertGroupBy;
  const scopeToggle = `<button type="button" id="ag-scope" class="agscope${S.alertGroupAll ? ' on' : ''}" title="Basculer entre alertes actives (status=new) et tous statuts (historique)">${S.alertGroupAll ? 'Tous statuts' : 'Actives'}</button>`;
  const count = typeof total === 'number' ? total : groups.length;
  const head = `<div class="alerthead"><span>${count} groupe(s) · par ${esc(axisLabel)}</span>${scopeToggle}</div>`;
  if (!groups.length) {
    b.innerHTML = alertViewControls(S.alertGroupBy) + head + `<div class="ok">Aucune alerte ${S.alertGroupAll ? '' : 'active '}à grouper</div>`;
    wireAlertViewControls(b); wireGroupScope(b); return;
  }
  // ui-regression — l'auto-refresh (30 s) reconstruit ce conteneur : on MÉMORISE les groupes
  // DÉPLIÉS + leur page d'occurrences AVANT le rebuild pour les RÉTABLIR après (sinon l'analyste perd sa place à
  // chaque tick : collapse + page 0, ce qui rend un groupe bruyant intravaillable). Clé = gkey (data-gkey).
  const prevOpen = {};
  b.querySelectorAll('.agroup.open').forEach(el => {
    const body = el.querySelector('.agbody');
    prevOpen[el.dataset.gkey || ''] = (body && body.dataset.opage) ? Number(body.dataset.opage) : 0;
  });
  b.innerHTML = alertViewControls(S.alertGroupBy) + head + groups.map(g => alertGroupHtml(g)).join('');
  wireAlertViewControls(b); wireGroupScope(b);
  { const gh = b.querySelector('.alerthead'); if (gh && groups.length) gh.appendChild(alertGroupsExportBar(groups, total)); }
  // pager de la LISTE de groupes (haut + bas), inséré autour des groupes.
  if (typeof total === 'number') {
    const pgState = { page: S.alertGroupPage, pageSize: ALERT_GROUP_PS, total, shown: groups.length };
    const go = p => { S.alertGroupPage = p; renderAlertGroups(true); };
    const top = makePager(pgState, go), bot = makePager(pgState, go);
    const first = b.querySelector('.agroup');
    if (top && first) b.insertBefore(top, first);
    if (bot) b.appendChild(bot);
  }
  // expand/collapse par groupe (chargement paresseux des occurrences au 1er dépli).
  b.querySelectorAll('.agroup').forEach((el, idx) => {
    const g = groups[idx];
    const sum = el.querySelector('.agsum');
    if (sum) sum.onclick = () => toggleAlertGroup(el, g);
    // RÉTABLIT l'état déplié + la page d'occurrences mémorisés avant le rebuild (cf. prevOpen ci-dessus).
    const gk = g.gkey || '';
    if (Object.prototype.hasOwnProperty.call(prevOpen, gk)) {
      const body = el.querySelector('.agbody');
      body.hidden = false; el.classList.add('open'); if (sum) sum.setAttribute('aria-expanded', 'true');
      loadGroupOccurrences(body, g, prevOpen[gk]);
    }
  });
}
function wireGroupScope(host) {
  const sc = host.querySelector('#ag-scope');
  if (sc) sc.onclick = () => { S.alertGroupAll = !S.alertGroupAll; S.alertGroupPage = 0; renderAlertGroups(true); };
}
// carte d'un GROUPE : en-tête cliquable (caret + sévérité + compte + clé + aperçu + activités + dernier ts) et
// un corps `.agbody` (occurrences) initialement replié/vide.
function alertGroupHtml(g) {
  const emptyLabel = S.alertGroupBy === 'host' ? '(sans hôte)' : S.alertGroupBy === 'mitre' ? '(sans technique)' : '(sans clé)';
  const key = g.gkey ? esc(g.gkey) : `<span class="muted">${emptyLabel}</span>`;
  const mt = (g.mitre && S.alertGroupBy !== 'mitre') ? ` <span class="mitrechip" title="${esc(g.mitre)}${mitreName(g.mitre) ? ' — ' + esc(mitreName(g.mitre)) : ''}">${esc(g.mitre)}</span>` : '';
  // cellule « actives » TOUJOURS émise (vide si 0) pour garder l'alignement de la grille .agsum stable.
  const open = g.open_n > 0 ? `<span class="agopen" title="${g.open_n} encore active(s) (status=new)">${g.open_n} active(s)</span>` : `<span class="agopen" style="visibility:hidden"></span>`;
  return `
  <div class="agroup sev-${g.severity}" data-gkey="${g.gkey ? esc(g.gkey) : ''}">
    <button type="button" class="agsum" aria-expanded="false">
      <span class="agcaret">${ic('chevright')}</span>
      <span class="sev">${sev(g.severity)}</span>
      <span class="agcount" title="${g.n} occurrence(s) dans ce groupe">${g.n}</span>
      <span class="agkey">${key}${mt}</span>
      <span class="agsample">${esc(g.sample_title || '')}</span>
      ${open}
      <time>${fmtTs(g.last_ts)}</time>
    </button>
    <div class="agbody" hidden></div>
  </div>`;
}
function toggleAlertGroup(el, g) {
  const body = el.querySelector('.agbody'), sum = el.querySelector('.agsum');
  if (!body.hidden) { body.hidden = true; el.classList.remove('open'); sum.setAttribute('aria-expanded', 'false'); return; }
  body.hidden = false; el.classList.add('open'); sum.setAttribute('aria-expanded', 'true');
  if (!body.dataset.loaded) loadGroupOccurrences(body, g, 0);
}
// OCCURRENCES d'un groupe (chemin plat, SCOPÉ au groupe via gkey/gval, MÊME scope statut que le groupement ->
// `total` cohérent avec `n`). Réutilise alertRowHtml + wireAlertRows + makePager. Après ack : recharge la même
// page d'occurrences (le groupe reste déplié).
async function loadGroupOccurrences(body, g, opage) {
  const scope = S.alertGroupAll ? 'all' : 'new';
  // MÊME scope uncased que le groupement (renderAlertGroups) -> `total` des occurrences cohérent avec `n`.
  const url = '/alerts?status=' + scope + (S.alertGroupAll ? '' : '&uncased=1') + '&gkey=' + encodeURIComponent(S.alertGroupBy)
            + '&gval=' + encodeURIComponent(g.gkey || '') + '&limit=' + ALERT_OCC_PS + '&offset=' + (opage * ALERT_OCC_PS);
  body.innerHTML = '<div class="tableprog"></div>';
  let occ, total;
  try { const r = await api(url); occ = r.alerts || []; total = r.total; }
  catch (e) { body.innerHTML = '<div class="bad">occurrences indisponibles : ' + esc(e.message) + '</div>'; return; }
  body.dataset.loaded = '1';
  body.dataset.opage = String(opage); // ui-regression : mémorise la page pour la restaurer après un rebuild (auto-refresh)
  body.innerHTML = occ.map((a, i) => alertRowHtml(a, i)).join('') || '<div class="muted">aucune occurrence</div>';
  if (typeof total === 'number') {
    const pgState = { page: opage, pageSize: ALERT_OCC_PS, total, shown: occ.length };
    const go = p => loadGroupOccurrences(body, g, p);
    const top = makePager(pgState, go), bot = makePager(pgState, go);
    const first = body.querySelector('.alert');
    if (top && first) body.insertBefore(top, first);
    if (bot) body.appendChild(bot);
  }
  wireAlertRows(body, occ, () => loadGroupOccurrences(body, g, opage));
}

export { renderAlerts, setAlertMitreFilter, setAlertSourceFilter };

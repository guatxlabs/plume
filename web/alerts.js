// alerts.js — file d'alertes : rendu, triage groupe, drill, export, filtres MITRE/source
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// Extrait d'app.js en PURE MOVE ; depuis P11.1 : lien de recherche servi par le démon, barre d'actions unique.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, esc, sev, fmtTs, ic, withBusy, api, apiSend, makePager, exportBar, confirmModal, mitreName } from './core.js';
import { S } from './state.js';
import { banIp, runQuery, updateZoomBadge } from './viz.js';
import { canEditCases, addToCase, openCase } from './cases.js';
import { refresh, updateRangeBtn } from './app.js';

// clic sur une alerte -> ouvre l'Explore sur ce que la règle a COMPTÉ.
// P11.1-a — LE LIEN EST CONSTRUIT PAR LE DÉMON (`search_link` sur /api/alerts : requête dont la règle a
// agrégé le résultat + fenêtre EXACTE de l'évaluation, cf. lien_de_recherche_de_regle). Le navigateur ne
// dérive plus rien pour une alerte de règle : une seule construction, la même que celle que le test
// `le_lien_de_chaque_regle_livree_reproduit_la_valeur_de_la_regle` exécute contre chaque règle livrée.
// Sans lien (alerte d'un collecteur, heartbeat, règle supprimée) : repli HEURISTIQUE historique — l'IP du
// titre, sinon le titre — sur la fenêtre de l'alerte ; ce repli n'est PAS un lien de recherche exact, et
// il ne concerne que les alertes qui ne viennent pas d'une règle (la propriété P11.1-a porte sur les règles).
// LIMITE CONNUE (hors de ce module) : la barre Explore ne reconnaît le GXQL que par `search` ou un `|`
// (viz.js runQuery) ; un lien `metric <nom>` nu — règle `metric … | stats max(value)` — y est pris pour du
// SQL brut. Le remède est dans viz.js (`looksLikeSoql` de soql_complete.js reconnaît `metric`).
function alertDrill(a) {
  if (!a) return;
  const lien = a.search_link && a.search_link.query ? a.search_link : null;
  let q;
  if (lien) {
    q = lien.query;
    // La fenêtre du lien est celle de l'évaluation : [ts - window_s, ts], sans marge — une marge rendait
    // le lien PLUS LARGE que le compte sur toutes les règles (mesuré P11.1-a).
    S.zoomRange = { from: lien.from, to: lien.to };
    updateZoomBadge(); if (typeof updateRangeBtn === 'function') updateRangeBtn();
  } else {
    const ipm = ((a.title || '') + ' ' + (a.detail || '')).match(ALERT_IP_RE);
    q = ipm ? ('search src_ip:' + ipm[0]) : ('search ' + (a.title || '').split(':')[0].trim());
    if (a.ts) {
      const w = (a.window_s || 3600);
      S.zoomRange = { from: Math.floor(a.ts - w), to: Math.ceil(a.ts) };
      updateZoomBadge(); if (typeof updateRangeBtn === 'function') updateRangeBtn();
    }
  }
  location.hash = 'explore';
  if ($('#sql')) { $('#sql').value = q; runQuery(); }
}
// PURPLE — filtre actif sur les alertes par technique MITRE (pivot depuis le panneau couverture ou un
// chip d'alerte). '' = aucun filtre (toutes les alertes). Cf. ?mitre= côté daemon (index idx_alert_mitre_ts,
// dont `mitre` est la colonne de TÊTE ; le idx_alert_mitre(mitre) seul, préfixe strict, a été retiré P10.2-d).
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
function setAlertGroupBy(g) { S.alertGroupBy = alert_group_axis(g) ? g : ''; S.alertGroupPage = 0; S.alertHistPage = 0; location.hash = 'alerts'; renderAlerts(true); }
function alert_group_axis(g) { return g === 'rule' || g === 'host' || g === 'mitre'; }
// le pivot MITRE amène vers Investigation -> Alertes (onglet #alerts, où vivent les Alertes actives, cf. SPACES).
// P11.1-b — un pivot MITRE pose une FACETTE sur la même liste : portée « tous statuts » (l'historique de
// détection de la technique, comportement historique), sans le filtre « hors case », tri inchangé.
function setAlertMitreFilter(m) {
  S.alertMitreFilter = (m || '').trim().toUpperCase(); S.alertSourceFilter = ''; S.alertHistPage = 0; S.alertGroupPage = 0;
  if (S.alertMitreFilter) { S.alertGroupAll = true; S.alertUncased = false; }
  location.hash = 'alerts'; renderAlerts(true);
}
// FIX 2 / P11.1-b — filtre actif sur les alertes par SOURCE (pivot depuis la cloche d'un feed « chaud » de
// la fraîcheur). '' = aucun filtre. Le filtre est SERVI par le démon (`?source=` sur /api/alerts et
// /api/alerts/groups) : un prédicat d'imputation EXACT sur `alert.sources`, l'imputation DÉRIVÉE DE LA
// DONNÉE à la levée de l'alerte — exactement ce qui fabrique le compteur `active_alerts` du feed dont on
// vient de cliquer la cloche. Les deux surfaces lisent le MÊME verdict, et la facette se combine avec tous
// les tris et les deux portées. Limite nommée : une alerte levée AVANT que l'imputation soit stockée (colonne
// vide) n'est appariée à aucune source par ce filtre, alors que la cloche la compte encore par le texte de
// sa règle.
/* state: alertSourceFilter -> S (state.js) */
// P11.1-c — la cloche d'une source pose la facette SOURCE sur la liste, avec la portée EXACTE du compteur de
// la cloche : alertes ACTIVES (status=new), cases comprises, TOUTES DATES (le compteur `active_alerts` de
// /api/freshness n'a pas de fenêtre de temps : il compte toute alerte non acquittée imputée à la source, quel
// que soit son âge — et il est indépendant de la fraîcheur de la source). La vue cible le DIT (cf. le chip
// de facette) et montre l'étendue réelle des dates des alertes listées. Le tri courant est conservé, comme
// pour le pivot technique.
function setAlertSourceFilter(src) {
  S.alertSourceFilter = (src || '').trim(); S.alertMitreFilter = ''; S.alertHistPage = 0; S.alertGroupPage = 0;
  if (S.alertSourceFilter) { S.alertGroupAll = false; S.alertUncased = false; }
  location.hash = 'alerts'; renderAlerts(true);
}
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
// ======================================================================================================
// P11.1-b — UNE LISTE, DES FACETTES, LES MÊMES ACTIONS PARTOUT. Plate / Règle / Hôte / Technique sont des
// TRIS d'une même liste, pas des écrans. MESURÉ avant correctif (web/alerts.js) : « Tous statuts » n'existait
// qu'en vue groupée, « Tout acquitter » qu'en vue plate sans filtre, le toggle de vue disparaissait sous un
// filtre, et le filtre « hors case » (uncased) variait en silence selon le chemin (plate : oui ; MITRE : non ;
// source : non ; groupes : selon la portée). Le modèle ci-dessous est UNIQUE et la barre est rendue par UNE
// fonction, quelle que soit la vue. Une action impossible n'est pas ABSENTE : elle est rendue désactivée avec
// sa raison (attribut `title`), pour qu'un lecteur sache ce qui manque et pourquoi.
// ======================================================================================================
// Le modèle de la liste : UN tri, UNE portée, UN filtre « hors case », des FACETTES.
function alertListModel() {
  return {
    view: S.alertGroupBy || '',               // '' plate | 'rule' | 'host' | 'mitre' (tri)
    scopeAll: !!S.alertGroupAll,              // false = actives (status=new) | true = tous statuts
    uncased: S.alertUncased !== false,        // alertes hors case seulement (défaut : oui)
    mitre: S.alertMitreFilter || '',          // facette technique (serveur, `?mitre=`)
    source: S.alertSourceFilter || '',        // facette source (serveur, `?source=`, imputation exacte)
  };
}
// Les deux facettes sont servies par le démon et s'appliquent à tous les tris et aux deux portées : aucune
// action n'est désactivée au motif d'une facette. L'URL d'une vue est dérivée du modèle par UNE fonction.
function alertFacetParams(m) {
  const p = [];
  if (m.mitre) p.push('mitre=' + encodeURIComponent(m.mitre));
  if (m.source) p.push('source=' + encodeURIComponent(m.source));
  return p;
}
const ALERT_VIEWS = [
  ['', 'Plate', 'Liste plate (chaque alerte)'],
  ['rule', 'Règle', 'Trier par règle — 1 groupe = N occurrences'],
  ['host', 'Hôte', 'Trier par hôte / entité'],
  ['mitre', 'Technique', 'Trier par technique MITRE ATT&CK'],
];
// Ce que la barre propose, DÉRIVÉ du modèle `m` et de ce qui est chargé (`loaded`) :
//   loaded.count / loaded.countLabel  — le compte affiché et sa portée en toutes lettres ;
//   loaded.ackableIds                 — les ids ACTIFS chargés (vue plate) ; vide en vue groupée ;
//   loaded.sourceSpan                 — {from,to} des alertes listées sous une facette source (P11.1-c).
// Rendu PUR (chaîne HTML) : le harnais ESM le juge sur des objets fabriqués.
function alertActionBarHtml(m, loaded) {
  loaded = loaded || {};
  const dis = (cond, reason) => cond ? ` disabled aria-disabled="true" title="${esc(reason)}"` : '';
  // P11.4-i — L'ÉTAT « CHOISI » PASSE PAR `aria-pressed`, ET PLUS PAR LA GRAISSE DU MOT. Le gras portait
  // déjà « alarme / valeur remarquable » ailleurs dans la console ; le réemployer ici faisait lire un tri
  // choisi comme une alerte. La marque visuelle est désormais le liseré réservé (`--sel-ring`, style.css)
  // et l'état lui-même est DIT : `aria-pressed` est le seul canal qu'une aide technique lit, et il ne
  // dépend d'aucune couleur. Il est posé sur les DEUX états — `false` compte autant que `true` : un
  // bouton bascule sans attribut se présente comme un simple bouton d'action.
  const views = ALERT_VIEWS.map(([g, label, title]) => `<button type="button" class="agseg${m.view === g ? ' on' : ''}" aria-pressed="${m.view === g}" data-g="${g}" title="${esc(title)}">${label}</button>`).join('');
  const scope = `<button type="button" class="agscope${m.scopeAll ? ' on' : ''}" aria-pressed="${m.scopeAll}" data-act="scope" title="${m.scopeAll ? 'Tous statuts (historique) — cliquer pour ne voir que les alertes actives' : 'Alertes actives (status=new) — cliquer pour voir tous les statuts'}">${m.scopeAll ? 'Tous statuts' : 'Actives'}</button>`;
  const uncased = `<button type="button" class="agscope${m.uncased ? ' on' : ''}" aria-pressed="${m.uncased}" data-act="uncased" title="${m.uncased ? 'Hors case : les alertes déjà rattachées à un case sont masquées — cliquer pour les inclure' : 'Toutes : cases comprises — cliquer pour masquer les alertes déjà rattachées à un case'}">${m.uncased ? 'hors case' : 'cases comprises'}</button>`;
  const facets = [];
  if (m.mitre) facets.push(`<span class="mitrefilter">Technique : <span class="mitrechip">${esc(m.mitre)}</span><button type="button" data-act="clear-mitre" title="Retirer le filtre technique">${ic('x')}</button></span>`);
  if (m.source) {
    const span = loaded.sourceSpan && loaded.sourceSpan.from ? ` (du ${fmtTs(loaded.sourceSpan.from)} au ${fmtTs(loaded.sourceSpan.to)})` : '';
    const n = typeof loaded.count === 'number' ? loaded.count : 0;
    // L'objet compté suit le tri et la portée : alertes en vue plate, groupes sinon ; actives ou tous statuts.
    const objet = m.view ? `${n} groupe(s) d'alertes ${m.scopeAll ? '(tous statuts)' : 'actives'}` : `${n} alerte(s) ${m.scopeAll ? '(tous statuts)' : 'active(s)'}`;
    facets.push(`<span class="mitrefilter" title="Le compteur de la cloche d'une source compte ses alertes non acquittées, cases comprises, sans fenêtre de temps — il ne dépend pas de la fraîcheur de la source.">Source : <span class="mitrechip">${esc(m.source)}</span> <span class="muted">${objet} imputée(s) à cette source, toutes dates${span} — sans lien avec sa fraîcheur</span><button type="button" data-act="clear-source" title="Retirer le filtre source">${ic('x')}</button></span>`);
  }
  // ACQUITTER — même bouton partout, sémantique DÉRIVÉE : sans facette et sur les actives, l'acquittement
  // GLOBAL (/alerts/ack-all acquitte TOUTE alerte active, y compris hors de la page) ; sinon, les alertes
  // actives AFFICHÉES, une à une (jamais un ack-all global sous un filtre : il dépasserait le filtre).
  const filtered = !!(m.mitre || m.source) || m.scopeAll;
  const nAck = (loaded.ackableIds || []).length;
  let ack;
  if (!filtered) ack = `<button type="button" class="btn btn-sm" data-act="ack-all"${dis(!(loaded.count > 0), 'aucune alerte active')} title="Acquitter TOUTES les alertes actives (y compris celles hors de cette page)">${ic('check')} Tout acquitter</button>`;
  else if (nAck > 0) ack = `<button type="button" class="btn btn-sm" data-act="ack-shown" title="Acquitter les ${nAck} alerte(s) active(s) affichée(s) — et seulement celles-là">${ic('check')} Acquitter les ${nAck} affichée(s)</button>`;
  else ack = `<button type="button" class="btn btn-sm" data-act="ack-shown"${dis(true, m.view ? 'acquittement par liste : dépliez un groupe (acquittement par occurrence) ou passez en vue plate' : 'aucune alerte active affichée')}>${ic('check')} Acquitter</button>`;
  return `<div class="alertview alertbar" role="toolbar" aria-label="Liste des alertes : tri, portée, filtres, actions">`
    + `<span class="muted">Tri</span>${views}<span class="muted">Portée</span>${scope}${uncased}${facets.join('')}</div>`
    + `<div class="alerthead"><span>${esc(loaded.countLabel || '')}</span><span class="alertbar-actions">${ack}<span class="alertbar-export"></span></span></div>`;
}
// Câblage de la barre : chaque action écrit le MODÈLE (état partagé) puis re-rend la liste par le même chemin.
function wireAlertActionBar(host, loaded) {
  const rerender = () => renderAlerts(true);
  host.querySelectorAll('.alertbar .agseg').forEach(btn => btn.onclick = () => { if (btn.disabled) return; setAlertGroupBy(btn.dataset.g); });
  host.querySelectorAll('[data-act]').forEach(btn => {
    const act = btn.dataset.act;
    if (act === 'scope') btn.onclick = () => { if (btn.disabled) return; S.alertGroupAll = !S.alertGroupAll; S.alertGroupPage = 0; S.alertHistPage = 0; rerender(); };
    else if (act === 'uncased') btn.onclick = () => { S.alertUncased = !(S.alertUncased !== false); S.alertGroupPage = 0; S.alertHistPage = 0; rerender(); };
    else if (act === 'clear-mitre') btn.onclick = () => setAlertMitreFilter('');
    else if (act === 'clear-source') btn.onclick = () => setAlertSourceFilter('');
    else if (act === 'ack-all') btn.onclick = () => withBusy(btn, async () => {
      if (btn.disabled) return;
      if (!await confirmModal(`Acquitter TOUTES les alertes actives ? (liste courante : ${loaded.countLabel || loaded.count} ; l'acquittement global porte aussi sur celles hors de la page)`, { okText: 'Acquitter', danger: false })) return;
      await apiSend('/alerts/ack-all');
      await refresh();
    });
    else if (act === 'ack-shown') btn.onclick = () => withBusy(btn, async () => {
      const ids = loaded.ackableIds || [];
      if (btn.disabled || !ids.length) return;
      if (!await confirmModal(`Acquitter les ${ids.length} alerte(s) active(s) affichée(s) ?`, { okText: 'Acquitter', danger: false })) return;
      for (const id of ids) await apiSend('/alerts/' + id + '/ack');
      await rerender();
    });
  });
}
// P11.1-d — LE TITRE « Alertes » EST UNE PORTE : comme tout en-tête qui nomme une page (liens `#onglet`
// de la navigation, `capsum-link` des cartes), il mène à la liste des alertes — tri plat, facettes retirées.
// Le bouton d'aide « ? » qu'il contient garde son propre comportement.
function wireAlertsTitle() {
  const h = $('#alerts-h'); if (!h || h.dataset.porte) return;
  h.dataset.porte = '1'; h.setAttribute('role', 'link'); h.tabIndex = 0; h.style.cursor = 'pointer';
  h.title = 'Liste des alertes (tri plat, filtres retirés)';
  const go = (e) => {
    if (e && e.target && typeof e.target.closest === 'function' && e.target.closest('.ihelp')) return;
    S.alertMitreFilter = ''; S.alertSourceFilter = ''; S.alertGroupBy = ''; S.alertGroupAll = false; S.alertUncased = true; S.alertHistPage = 0; S.alertGroupPage = 0;
    location.hash = 'alerts'; renderAlerts(true);
  };
  h.onclick = go;
  h.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(e); } };
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
  wireAlertsTitle();
  const m = alertListModel();
  // Un TRI groupé est servi par /api/alerts/groups, facettes comprises.
  if (m.view) return renderAlertGroups(loading);
  // LA MÊME URL DÉRIVÉE DU MÊME MODÈLE : portée (status=new | all), « hors case » (uncased=1), facettes
  // (mitre=, source=). La portée « tous statuts » est PAGINÉE serveur (limit/offset + total) ; la portée
  // « actives » reste bornée (200, sans total) — contrat inchangé de /api/alerts.
  const params = [];
  params.push(m.scopeAll ? 'status=all' : 'status=new');
  if (m.uncased) params.push('uncased=1');
  params.push(...alertFacetParams(m));
  if (m.scopeAll) params.push('limit=' + ALERT_HIST_PS + '&offset=' + (S.alertHistPage * ALERT_HIST_PS));
  const url = '/alerts?' + params.join('&');
  const b = $('#alerts .body'); if (!b) return;
  if (loading) { let prog = b.querySelector(':scope > .tableprog'); if (!prog) { prog = document.createElement('div'); prog.className='tableprog'; b.insertBefore(prog, b.firstChild); } prog.hidden=false; b.classList.add('reloading'); }
  let alerts, alertTotal;
  try { const resp = await api(url); alerts = resp.alerts || []; alertTotal = resp.total; } catch (e) { b.classList.remove('reloading'); b.innerHTML = '<div class="bad">alertes indisponibles : ' + esc(e.message) + '</div>'; return; }
  b.classList.remove('reloading');
  // Facette SOURCE : filtrée par le serveur ; l'étendue des dates des alertes LISTÉES (la page courante sous
  // la portée « tous statuts ») est affichée à côté du chip.
  let sourceSpan = null;
  if (m.source && alerts.length) { const ts = alerts.map(a => a.ts).filter(Boolean); sourceSpan = { from: Math.min(...ts), to: Math.max(...ts) }; }
  const count = (m.scopeAll && typeof alertTotal === 'number') ? alertTotal : alerts.length;
  const portee = (m.scopeAll ? 'tous statuts' : 'actives') + (m.uncased ? ' · hors case' : ' · cases comprises');
  const loaded = {
    count,
    countLabel: `${count} alerte(s) · ${portee}${m.mitre ? ' · technique ' + m.mitre : ''}${m.source ? ' · source ' + m.source : ''}`,
    ackableIds: alerts.filter(a => a.status === 'new').map(a => a.id),
    sourceSpan,
  };
  const bar = alertActionBarHtml(m, loaded);
  if (!alerts.length) {
    let vide;
    if (m.mitre) {
      // 0 alerte même TOUS statuts -> on propose de voir les events de la technique (pas de cul-de-sac)
      vide = `<div class="muted">Aucune alerte (${esc(portee)}) pour cette technique. <button id="mitre-events" type="button" class="linklike">Voir les events ${esc(m.mitre)}</button></div>`;
    } else if (m.source) {
      vide = `<div class="muted">Aucune alerte (${esc(portee)}) imputée à la source <b>${esc(m.source)}</b>.</div>`;
    } else {
      vide = `<div class="ok">Aucune alerte ${m.scopeAll ? '' : 'active '}${m.uncased ? 'hors case ' : ''}</div>`;
    }
    b.innerHTML = bar + vide;
    const ev = b.querySelector('#mitre-events'); if (ev) ev.onclick = () => mitreEventsDrill(m.mitre);
    wireAlertActionBar(b, loaded);
    return;
  }
  b.innerHTML = bar + alerts.map((a, i) => alertRowHtml(a, i)).join('');
  wireAlertActionBar(b, loaded);
  // WIRING des lignes (drill/ack/ban/case) : ack -> re-render de la liste filtrée, ou refresh global (backlog).
  wireAlertRows(b, alerts, () => (m.mitre || m.source || m.scopeAll) ? renderAlerts() : refresh());
  // EXPORT : barre CSV/JSON/PDF dans l'emplacement de la barre d'actions (sur les alertes chargées).
  { const slot = b.querySelector('.alertbar-export'); if (slot) slot.appendChild(alertsExportBar(alerts, m.scopeAll ? alertTotal : undefined)); }
  // pager (haut+bas) sur la portée « tous statuts » (serveur limit/offset) ; auto-caché si <=1 page.
  if (m.scopeAll && typeof alertTotal === 'number') {
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
// paginé). Le modèle (portée / hors case / facettes technique et source) est le MÊME que celui de la vue plate, et
// s'applique À LA FOIS au groupement et à l'expansion -> le compteur `n` du groupe et le `total` des
// occurrences restent COHÉRENTS.
async function renderAlertGroups(loading) {
  const b = $('#alerts .body'); if (!b) return;
  const m = alertListModel();
  const url = '/alerts/groups?group=' + encodeURIComponent(m.view) + '&status=' + (m.scopeAll ? 'all' : 'new')
            + (m.uncased ? '&uncased=1' : '')
            + alertFacetParams(m).map(p => '&' + p).join('')
            + '&limit=' + ALERT_GROUP_PS + '&offset=' + (S.alertGroupPage * ALERT_GROUP_PS);
  if (loading) { let prog = b.querySelector(':scope > .tableprog'); if (!prog) { prog = document.createElement('div'); prog.className='tableprog'; b.insertBefore(prog, b.firstChild); } prog.hidden=false; b.classList.add('reloading'); }
  let groups, total;
  try { const r = await api(url); groups = r.groups || []; total = r.total; }
  catch (e) { b.classList.remove('reloading'); b.innerHTML = alertActionBarHtml(m, { count: 0, countLabel: 'groupes indisponibles' }) + '<div class="bad">groupes indisponibles : ' + esc(e.message) + '</div>'; wireAlertActionBar(b, { count: 0 }); return; }
  b.classList.remove('reloading');
  const axisLabel = { rule: 'règle', host: 'hôte', mitre: 'technique' }[m.view] || m.view;
  const count = typeof total === 'number' ? total : groups.length;
  const portee = (m.scopeAll ? 'tous statuts' : 'actives') + (m.uncased ? ' · hors case' : ' · cases comprises');
  const loaded = { count, countLabel: `${count} groupe(s) · par ${axisLabel} · ${portee}${m.mitre ? ' · technique ' + m.mitre : ''}${m.source ? ' · source ' + m.source : ''}`, ackableIds: [] };
  const bar = alertActionBarHtml(m, loaded);
  if (!groups.length) {
    b.innerHTML = bar + `<div class="ok">Aucune alerte ${m.scopeAll ? '' : 'active '}à trier${m.source ? ` pour la source ${esc(m.source)}` : ''}</div>`;
    wireAlertActionBar(b, loaded); return;
  }
  // ui-regression — l'auto-refresh (30 s) reconstruit ce conteneur : on MÉMORISE les groupes
  // DÉPLIÉS + leur page d'occurrences AVANT le rebuild pour les RÉTABLIR après (sinon l'analyste perd sa place à
  // chaque tick : collapse + page 0, ce qui rend un groupe bruyant intravaillable). Clé = gkey (data-gkey).
  const prevOpen = {};
  b.querySelectorAll('.agroup.open').forEach(el => {
    const body = el.querySelector('.agbody');
    prevOpen[el.dataset.gkey || ''] = (body && body.dataset.opage) ? Number(body.dataset.opage) : 0;
  });
  b.innerHTML = bar + groups.map(g => alertGroupHtml(g)).join('');
  wireAlertActionBar(b, loaded);
  { const slot = b.querySelector('.alertbar-export'); if (slot) slot.appendChild(alertGroupsExportBar(groups, total)); }
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
// carte d'un GROUPE : en-tête cliquable (caret + sévérité + compte + clé + aperçu + activités + dernier ts) et
// un corps `.agbody` (occurrences) initialement replié/vide.
function alertGroupHtml(g) {
  const view = S.alertGroupBy || '';
  const emptyLabel = view === 'host' ? '(sans hôte)' : view === 'mitre' ? '(sans technique)' : '(sans clé)';
  const key = g.gkey ? esc(g.gkey) : `<span class="muted">${emptyLabel}</span>`;
  const mt = (g.mitre && view !== 'mitre') ? ` <span class="mitrechip" title="${esc(g.mitre)}${mitreName(g.mitre) ? ' — ' + esc(mitreName(g.mitre)) : ''}">${esc(g.mitre)}</span>` : '';
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
  const m = alertListModel();
  // MÊME modèle que le groupement (renderAlertGroups) -> `total` des occurrences cohérent avec `n`.
  const url = '/alerts?status=' + (m.scopeAll ? 'all' : 'new') + (m.uncased ? '&uncased=1' : '')
            + alertFacetParams(m).map(p => '&' + p).join('')
            + '&gkey=' + encodeURIComponent(m.view)
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

export { renderAlerts, setAlertMitreFilter, setAlertSourceFilter, alertActionBarHtml, alertListModel };

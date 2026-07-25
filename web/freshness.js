// freshness.js — panneaux « Fraîcheur (santé par source) » + « Intégrations (couverture capteurs/hôtes) »
// de la Vue d'ensemble, extraits d'app.js (1re découpe par CONCERN). Comportement
// IDENTIQUE au monolithe : fonctions simplement relocalisées, aucune logique modifiée. Dépend uniquement de
// core.js (helpers DOM/api/esc/ic), state.js (S : freshnessRepollTimer/freshCollapsed) et d'UN export d'app.js
// (setAlertSourceFilter, pour le pivot cloche « source chaude » -> alertes filtrées). Le cycle app<->freshness
// est sans danger : setAlertSourceFilter n'est appelé qu'à l'EXÉCUTION (clic), jamais à l'évaluation du module.
// collapsibleGroup vit dans core.js (helper PARTAGÉ règles/parseurs/actions/playbooks) ; il n'est pas un
// membre du concern Fraîcheur (que renderFreshness/renderIntegrations n'appellent pas) — d'où non importé ici.
import { $, api, esc, fmtTs, ic } from './core.js';
import { S } from './state.js';
import { setAlertSourceFilter } from './app.js';

async function renderIntegrations() {
  const b = $('#integrations .body'); if (!b) return;
  let d; try { d = await api('/integrations'); } catch (e) { return; }
  const collectors = d.collectors || [];
  // batch-2 item 1 — RECADRAGE : cette carte n'est PLUS un 2e compteur de santé qui doublonne (et contredit)
  // Fraîcheur. Elle répond à une AUTRE question : la COUVERTURE de capteurs (types de sondes déclarés en code)
  // + les HÔTES (où les agents poussent). On ne compte donc plus actif/muet (santé d'une source vivante = rôle
  // de Fraîcheur) mais la couverture : combien de capteurs DÉCLARÉS sont BRANCHÉS (ont déjà remonté ≥1 donnée)
  // vs EN ATTENTE (déclarés, jamais vus = ex-'inconnu', ex. YARA). « capteur » = TYPE de sonde (≠ « source » :
  // un capteur peut se déployer en N sources). Dénominateur explicite (« N déclarés ») -> l'écart avec le nombre
  // de sources de Fraîcheur devient COMPRIS (granularité sonde vs source), pas contradictoire.
  const waiting = collectors.filter(c => c.status === 'inconnu' || c.last_seen == null);
  // ANTI-ANGLE-MORT : un capteur CONTINU (event_based=false : controls/web/kube-audit/resources…) qui décroche
  // INDIVIDUELLEMENT passe 'muet' (>3x son intervalle) MÊME si le pipeline global reste frais. Fraîcheur ne juge
  // 'muet' que le pipeline GLOBAL -> elle le montre 'calme', PAS muet. Cette carte est donc le SEUL coup d'œil UI
  // sur ce capteur mort (l'alerte heartbeat n'arrive qu'à 5x). On garde donc une pastille muet ROUGE ici : on ne
  // réduit pas la visibilité (invariant opérateur). Compteurs additifs : déclarés = branchés + muets + en attente.
  const mute = collectors.filter(c => c.status === 'muet');
  const total = collectors.length, connected = total - waiting.length - mute.length;
  const pill = (dot, lbl, cnt) => `<span class="capsum-pill"><span class="fdot ${dot}"></span>${cnt} ${lbl}</span>`;
  const withNames = (arr) => { const nm = arr.map(c => esc(c.label || c.id)).join(', '); return nm ? ` <span class="muted" style="font-size:11px">(${nm})</span>` : ''; };
  // muet : capteur branché puis décroché (dead-man's-switch continu). ROUGE = alerte : à investiguer.
  const mutePill = mute.length ? pill('muet', 'muet(s)', mute.length) + withNames(mute) : '';
  // en attente : liste inline des sondes déclarées-jamais-vues (remplace le bloc « Non branché » codé en dur :
  // YARA EST le en_attente data-driven -> sa pastille disparaît d'elle-même dès qu'un event source=yara arrive).
  const waitPill = waiting.length ? pill('attente', 'en attente', waiting.length) + withNames(waiting) : '';
  // « branché(s) » = pastille NEUTRE (pas de couleur santé) : c'est de la COUVERTURE, pas de la fraîcheur
  // (le vert=frais reste réservé à Fraîcheur) -> l'opérateur ne confond plus les deux compteurs.
  const capsum = `<div class="capsum"><span class="capsum-pill"><b>${total}</b>&nbsp;capteurs déclarés</span>${connected ? `<span class="capsum-pill">${connected} branché(s)</span>` : ''}${mutePill}${waitPill}` +
    `<a class="capsum-link" href="#freshness-view" title="Santé par source (frais/calme/dégradé/muet) : Données → Fraîcheur">santé des sources →</a>` +
    `<a class="capsum-link" href="#sources" title="Inventaire complet des sources (Données → Sources)">inventaire →</a></div>`;
  const hosts = (d.hosts || []).length
    ? d.hosts.map(h => `<div class="kv"><span>${ic('server')} ${esc(h.host)}</span><span class="muted">${fmtTs(h.last_seen)}</span></div>`).join('')
    : '<div class="muted">hôte local uniquement — aucun agent distant n\'a encore poussé de logs.</div>';
  // caption : sépare EXPLICITEMENT les 2 axes (couverture de sondes vs endpoints) et renvoie la SANTÉ à Fraîcheur.
  const cap = `<div class="muted intplug" style="font-size:11px">Capteurs = <b>couverture</b> (types de sondes déclarés ; un capteur mort est signalé <b>muet</b> ici) · Hôtes = <b>endpoints</b> (où les agents poussent). La santé fine par source (frais/calme/dégradé) vit dans Fraîcheur.</div>`;
  // lien de découverte -> la Flotte (inventaire détaillé des hôtes : statut/enrôlement/dernier signal, paginé + export).
  const hostsHdr = `Hôtes (endpoints) <a class="capsum-link" href="#fleet" title="Flotte d'agents : inventaire détaillé (statut, enrôlement, dernier signal) — Données → Flotte">flotte →</a>`;
  b.innerHTML = `<div class="intgrid"><div><div class="fldname">Capteurs (couverture)</div>${capsum}</div><div><div class="fldname">${hostsHdr}</div>${hosts}</div></div>${cap}`;
}
// fraîcheur PAR SOURCE : âge du dernier point + statut (cadence estimée côté serveur). "Est-ce live ?"
/* state: freshnessRepollTimer -> S (state.js) */   // re-poll rapproché quand le serveur calcule encore (warming)
// état de pliage persisté (l'auto-refresh re-rend le panneau -> on ne ré-ouvre pas à chaque tick).
// Clé unique 'metric-open' = les 36 séries métriques sont dépliées.
// Par défaut (1re visite, clé absente) on ne replie QUE le groupe « calme » (sources peu actives, OK).
/* state: freshCollapsed -> S (state.js) */
// état à 4 niveaux d'un feed : rouge (muet/panne) > orange (émet mais dégradé/en retard) >
// vert (frais) > bleu (calme). L'orange est DÉRIVÉ (aucun nouveau champ serveur) : la source
// émet (pas muette) MAIS a des alertes actives, OU son âge dépasse largement sa cadence (4x, plancher
// 15 min POUR LES PÉRIODIQUES ; 1 h pour les continus — cf. isContinu/F-ui6 ci-dessous).
// batch-2 item 1 — état CANONIQUE d'un feed, partagé (projection) par les 3 surfaces santé-sources :
//   muet(rouge) > en_attente(gris) > dégradé/warn(orange) > frais(vert) > calme(bleu).
//   « en_attente » = capteur/source DÉCLARÉ mais JAMAIS de donnée (status 'inconnu'/'attente' côté daemon,
//   ex. YARA) — distinct de « calme » (a des données mais tranquille). Dérivé du STATUT (pas de last_seen :
//   les séries métriques n'ont pas ce champ), donc inerte pour les feeds de /freshness (tous ont des données)
//   et actif pour les collecteurs (renderIntegrations) où YARA remonte 'inconnu'.
// F-ui6 — isContinu : cadence HAUTE (≤ 90 s entre données) = MÊME seuil que le serveur (daemon
// freshness.rs:231, typ "continu"). Pour ces feeds expected_s*4 ≤ 360 s << 900 s : l'ancien plancher
// 900 s les faisait basculer frais→dégradé pile à 15 min, SANS bande calme — contredisant l'Inventaire
// des sources (/api/sources, plancher plat 900 s) qui les montre frais→calme. On relève donc le plancher
// à 3600 s POUR EUX SEULS : bande calme jusqu'à 1 h, dégradé seulement si vraiment en retard (>1 h) ou
// alertes actives. Les périodiques (expected_s > 90) gardent le plancher 900, mais expected_s*4 domine
// -> cloudflare/kube-audit signalent toujours quand ILS sont réellement en retard (INCHANGÉ).
const isContinu = f => f.expected_s > 0 && f.expected_s <= 90;
function freshState(f) {
  if (f.status === 'muet') return 'muet';
  if (f.status === 'inconnu' || f.status === 'attente' || f.status === 'en_attente') return 'attente';
  if (Number(f.active_alerts) > 0) return 'warn';
  const lateFloor = isContinu(f) ? 3600 : 900;   // continu : bande calme jusqu'à 1 h ; périodique : inchangé
  if (f.expected_s > 0 && f.age_s > Math.max(lateFloor, f.expected_s * 4)) return 'warn';
  return f.status === 'frais' ? 'frais' : 'calme';
}
// classe de couleur du texte (le <b> "il y a …") par état
const FSTATE_TXT = { muet: 'bad', warn: 'fwarn', frais: 'ok', calme: 'calm', attente: 'mut' };
// libellé d'en-tête de groupe quand on regroupe PAR ÉTAT (muet / en attente / dégradé / frais / calme)
const FSTATE_LBL = { muet: 'muet — collecte en panne', attente: 'en attente — déclaré, pas encore de donnée', warn: 'dégradé / en retard', frais: 'frais (<15 min)', calme: 'calme (peu actif, OK)' };
async function renderFreshness(loading) {
  // Le DÉTAIL complet vit désormais dans l'onglet Données → Fraîcheur (#freshness-panel).
  // La Vue d'ensemble (#freshness) ne garde qu'un pulse compact (renderFreshnessPulse ci-dessous).
  const b = $('#freshness-panel .body'); if (!b) return;
  // barre de chargement RÉUTILISÉE : exactement la même .tableprog que l'Explore (#qprog), les panneaux de
  // Dashboards et la file d'Alertes (cf. renderAlerts) — PAS une variante ad-hoc. Montrée pendant le refresh
  // manuel (#fresh-refresh -> renderFreshness(true)), masquée à la fin : la reconstruction de l'innerHTML
  // (tous les chemins de succès) retire la barre ; .reloading est retiré juste après le fetch (succès/erreur).
  if (loading) { let prog = b.querySelector(':scope > .tableprog'); if (!prog) { prog = document.createElement('div'); prog.className = 'tableprog'; b.insertBefore(prog, b.firstChild); } prog.hidden = false; b.classList.add('reloading'); }
  let d; try { d = await api('/freshness'); } catch (e) { b.classList.remove('reloading'); const p = b.querySelector(':scope > .tableprog'); if (p) p.hidden = true; return; }
  b.classList.remove('reloading');
  const feeds = d.feeds || [];
  // FROID : le serveur calcule la fraîcheur en async (~5s, scan 7j chiffré) et renvoie warming SANS bloquer.
  // On affiche un placeholder « … » (PAS un vide-définitif) et on re-poll de façon rapprochée jusqu'à ce que
  // la vraie valeur arrive — au lieu d'attendre le prochain tick d'auto-refresh (30s).
  if (d.warming) {
    clearTimeout(S.freshnessRepollTimer);
    S.freshnessRepollTimer = setTimeout(renderFreshness, 3000);
    if (!feeds.length) { b.innerHTML = '<div class="muted">… mesure de la fraîcheur des sources en cours</div>'; return; }
    // (cas rare) warming avec dernières valeurs connues -> on retombe sur l'affichage normal ci-dessous.
  } else {
    clearTimeout(S.freshnessRepollTimer); S.freshnessRepollTimer = null;
  }
  if (!feeds.length) { b.innerHTML = '<div class="muted">aucun feed récent</div>'; return; }
  const SRANK = { muet: 0, attente: 1, warn: 2, frais: 3, calme: 4 };   // panne en haut ; puis en attente, dégradé, frais, calme
  feeds.sort((a, c) => ((SRANK[freshState(a)] ?? 9) - (SRANK[freshState(c)] ?? 9)) || a.name.localeCompare(c.name));
  const age = s => s < 90 ? s + ' s' : s < 5400 ? Math.round(s / 60) + ' min' : s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' j';
  // le STATUT = santé de collecte : muet seulement si l'ingestion est en panne ; sinon l'âge est INFORMATIF
  const head = !d.pipeline_fresh
    ? `<div class="bad" style="font-weight:600;margin-bottom:8px">${ic('warn')} Ingestion en panne — aucune donnée reçue récemment</div>`
    : `<div class="muted" style="margin-bottom:8px">Collecte OK. L'âge = temps depuis la dernière donnée (dépend de l'activité de la source — ce n'est pas un retard).</div>`;
  // batch-2 item 2 — une SÉRIE métrique (sous le feed agrégé déplié) : même modèle d'état que les sources.
  const seriesRow = s => {
    const ss = freshState({ status: s.status, age_s: s.age_s, expected_s: 0, active_alerts: 0 });
    return `<div class="kv fseries"><span><span class="fdot ${ss}"></span>${esc(s.name)}</span>` +
      `<b class="${FSTATE_TXT[ss] || 'bad'}" title="dernière donnée ${fmtTs(s.last_seen)}">il y a ${age(s.age_s)}</b></div>`;
  };
  // une ligne par source ; surlignée (classe .hot + badge) si la source a des alertes actives (active_alerts>0).
  const rowOf = f => {
    const st = freshState(f);
    // batch-2 item 2 — le FEED MÉTRIQUE n'est plus « à part » : il est rangé dans SON groupe d'état comme
    // les autres sources, MAIS reste dépliable (chevron) pour révéler ses N séries (chacune avec sa pastille).
    // Persistance du pliage inchangée (clé 'metric-open'). Aucune donnée perdue : le détail est déplié au clic.
    if (f.kind === 'metric') {
      const sList = f.series || [];
      const open = S.freshCollapsed.has('metric-open');
      const body = sList.length
        ? `<div class="fmetricbody">${sList.map(seriesRow).join('')}</div>`
        : `<div class="fmetricbody muted" style="padding:4px 0 0 18px">détail des séries indisponible (mettre à jour le daemon)</div>`;
      const hd = `<div class="kv fmetrichd" role="button" tabindex="0" aria-expanded="${open ? 'true' : 'false'}" title="Plier / déplier les séries métriques">` +
        `<span><span class="fchev">${ic('chevright')}</span><span class="fdot ${st}"></span>${esc(f.name)} <span class="muted fkind">${esc(f.type || 'continu')}</span></span>` +
        `<b class="${FSTATE_TXT[st] || 'bad'}">il y a ${age(f.age_s)}</b></div>`;
      return `<div class="fmetric${open ? '' : ' collapsed'}">${hd}${body}</div>`;
    }
    const hot = Number(f.active_alerts) > 0;
    const badge = hot ? ` <span class="fhot" role="button" tabindex="0" data-src="${esc(f.name)}" title="Voir les ${f.active_alerts} alerte(s) de ${esc(f.name)}">${ic('bell')} ${f.active_alerts}</span>` : '';
    // F-ui6 — quand un feed est DÉGRADÉ (warn), on EXPLIQUE pourquoi : alertes actives OU retard cadence.
    // La raison complète est posée en title= sur la ligne ; un indice inline discret « · en retard » est
    // ajouté pour le cas retard (le cas alertes a déjà la pastille cloche visible ci-dessus).
    const reason = st === 'warn'
      ? (hot ? `dégradé — ${f.active_alerts} alerte(s) active(s)`
             : `dégradé — en retard (pas de donnée depuis ${age(f.age_s)})`)
      : '';
    const why = (reason && !hot) ? ` <span class="muted fwhy">· en retard</span>` : '';
    return `<div class="kv${hot ? ' hot' : ''}"${reason ? ` title="${esc(reason)}"` : ''}><span><span class="fdot ${st}"></span>${esc(f.name)} <span class="muted fkind">${esc(f.type || f.kind)}</span>${badge}${why}</span>` +
      `<b class="${FSTATE_TXT[st] || 'bad'}" title="${f.expected_s ? 'cadence ~' + age(f.expected_s) + ' · ' : ''}dernière donnée ${fmtTs(f.last_seen)}">il y a ${age(f.age_s)}</b></div>`;
  };
  // GROUPES PAR ÉTAT : on regroupe les sources (hors métriques) par leur ÉTAT de fraîcheur
  // (muet / dégradé / frais / calme). Chaque état est une section repliable : en-tête cliquable
  // (libellé + nombre + pastille = l'état du groupe lui-même), tri DANS le groupe le plus PÉRIMÉ
  // d'abord (age décroissant). Le type de cadence reste visible sur chaque ligne (.fkind).
  // Par défaut seul « calme » est replié (voir init de freshCollapsed). État persisté dans
  // freshCollapsed (clé 'cat:<état>' présente = REPLIÉ ; absente = déplié). Le feed métrique
  // agrégé garde son propre repliable existant (clé 'metric-open').
  // batch-2 item 2 — les métriques ne sont PLUS séparées (fini nonMetric/bloc .fmetric à part) : le feed
  // métrique est un feed comme les autres, classé dans son groupe d'état via freshState (rowOf le rend
  // dépliable). Le dénominateur de Fraîcheur inclut donc le feed métrique.
  const freshCat = f => freshState(f);
  const groups = new Map();
  feeds.forEach(f => { const c = freshCat(f); if (!groups.has(c)) groups.set(c, []); groups.get(c).push(f); });
  // ordre des groupes par SRANK : muet -> en attente -> warn -> frais -> calme
  const cats = [...groups.entries()].sort((a, c) => (SRANK[a[0]] ?? 9) - (SRANK[c[0]] ?? 9));
  // C7 — la carte Fraîcheur = un COUP D'ŒIL : résumé compact (compteurs par état) + lien vers l'inventaire
  // gérable (Données → Sources). Le détail par source reste dessous (groupes repliables), l'inventaire complet
  // et éditable vit dans Données → Sources (dédup de surface, aucune donnée perdue). Dénominateur explicite.
  const scount = { frais: 0, calme: 0, warn: 0, muet: 0, attente: 0 };
  feeds.forEach(f => { const s = freshState(f); scount[s] = (scount[s] || 0) + 1; });
  const sumPill = (dot, lbl, c) => c ? `<span class="capsum-pill"><span class="fdot ${dot}"></span>${c} ${lbl}</span>` : '';
  const summaryLine = `<div class="capsum"><span class="capsum-pill"><b>${feeds.length}</b>&nbsp;feed(s) observé(s)</span>${sumPill('frais', 'frais', scount.frais)}${sumPill('calme', 'calme', scount.calme)}${sumPill('warn', 'dégradé', scount.warn)}${sumPill('attente', 'en attente', scount.attente)}${sumPill('muet', 'muet', scount.muet)}` +
    `<a class="capsum-link" href="#sources" title="Ouvrir l'inventaire complet des sources (Données → Sources)">voir l'inventaire →</a></div>`;
  let html = head + summaryLine;
  for (const [cat, arr] of cats) {
    // au sein d'un groupe : la plus périmée d'abord (age décroissant), puis nom
    arr.sort((a, c) => (c.age_s - a.age_s) || a.name.localeCompare(c.name));
    const collapsed = S.freshCollapsed.has('cat:' + cat);
    const worst = cat;   // la pastille du groupe = l'état du groupe lui-même
    const lbl = FSTATE_LBL[cat] || cat;
    html += `<div class="fgroup${collapsed ? ' collapsed' : ''}" data-cat="${esc(cat)}">` +
      `<button type="button" class="fgrouphd" aria-expanded="${collapsed ? 'false' : 'true'}" title="Plier / déplier ${esc(lbl)}">` +
      `${ic('chevdown')}<span class="fdot ${worst}"></span><span class="fglbl">${esc(lbl)}</span><span class="fgcount">${arr.length}</span></button>` +
      `<div class="fgbody">${arr.map(rowOf).join('')}</div></div>`;
  }
  // batch-2 item 2 — plus de bloc métrique séparé ici : le feed métrique est rendu dans son groupe d'état
  // ci-dessus (rowOf gère le dépliage des séries). Le handler du chevron reste attaché plus bas (.fmetrichd).
  html += `<div class="flegend"><span class="fdot frais"></span>frais &lt;15 min · <span class="fdot calme"></span>calme (peu active, OK) · <span class="fdot warn"></span>dégradé / en retard · <span class="fdot attente"></span>en attente (déclaré, pas de donnée) · <span class="fdot muet"></span>muet (collecte en panne)` +
    `<div class="muted" style="margin-top:4px">Fraîcheur signale en plus <b>dégradé</b> les sources avec alertes actives ou en retard au-delà de leur cadence : une source peut donc lire <b>calme</b> dans l'Inventaire (Données → Sources) et <b>dégradé</b> ici, par conception.</div></div>`;
  b.innerHTML = html;
  // pliage des groupes par catégorie (persisté : 'cat:<type>' présent = replié ; défaut = déplié)
  b.querySelectorAll('.fgrouphd').forEach(hd => {
    const toggle = () => {
      const wrap = hd.closest('.fgroup'); const cat = wrap.dataset.cat;
      const nowCollapsed = wrap.classList.toggle('collapsed');
      hd.setAttribute('aria-expanded', nowCollapsed ? 'false' : 'true');
      if (nowCollapsed) S.freshCollapsed.add('cat:' + cat); else S.freshCollapsed.delete('cat:' + cat);
      try { localStorage.setItem('soc_fresh_collapsed', JSON.stringify([...S.freshCollapsed])); } catch (e) {}
    };
    hd.onclick = toggle;
    hd.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } };
  });
  // FIX 2 — cloche d'une source « chaude » cliquable -> alertes filtrées par CETTE source (#notifications)
  b.querySelectorAll('.fhot[data-src]').forEach(el => {
    const go = e => { e.stopPropagation(); setAlertSourceFilter(el.dataset.src); };
    el.onclick = go;
    el.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(e); } };
  });
  const md = b.querySelector('.fmetrichd');
  if (md) {
    const toggle = () => {
      const wrap = md.closest('.fmetric');
      const nowOpen = !wrap.classList.toggle('collapsed');   // toggle renvoie true si MAINTENANT collapsed
      md.setAttribute('aria-expanded', nowOpen ? 'true' : 'false');
      if (nowOpen) S.freshCollapsed.add('metric-open'); else S.freshCollapsed.delete('metric-open');
      try { localStorage.setItem('soc_fresh_collapsed', JSON.stringify([...S.freshCollapsed])); } catch (e) {}
    };
    md.onclick = toggle;
    md.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } };
  }
}

// PULSE compact de la Vue d'ensemble (#freshness) : SEULEMENT les compteurs par état
// (N feeds / frais / calme / dégradé / en attente / muet) + un lien « voir le détail → » vers l'onglet
// Données → Fraîcheur (#freshness-view). PAS de drilldown par feed ici (il vit dans #freshness-panel, via
// renderFreshness). Réutilise EXACTEMENT la même agrégation freshState/scount que le détail.
async function renderFreshnessPulse() {
  const b = $('#freshness .body'); if (!b) return;
  let d; try { d = await api('/freshness'); } catch (e) { return; }
  const feeds = d.feeds || [];
  if (d.warming && !feeds.length) { b.innerHTML = '<div class="muted">… mesure de la fraîcheur des sources en cours</div>'; return; }
  if (!feeds.length) { b.innerHTML = '<div class="muted">aucun feed récent</div>'; return; }
  const scount = { frais: 0, calme: 0, warn: 0, muet: 0, attente: 0 };
  feeds.forEach(f => { const s = freshState(f); scount[s] = (scount[s] || 0) + 1; });
  const sumPill = (dot, lbl, c) => c ? `<span class="capsum-pill"><span class="fdot ${dot}"></span>${c} ${lbl}</span>` : '';
  const head = !d.pipeline_fresh
    ? `<div class="bad" style="font-weight:600;margin-bottom:8px">${ic('warn')} Ingestion en panne — aucune donnée reçue récemment</div>`
    : '';
  b.innerHTML = head +
    `<div class="capsum"><span class="capsum-pill"><b>${feeds.length}</b>&nbsp;feed(s) observé(s)</span>` +
    `${sumPill('frais', 'frais', scount.frais)}${sumPill('calme', 'calme', scount.calme)}${sumPill('warn', 'dégradé', scount.warn)}${sumPill('attente', 'en attente', scount.attente)}${sumPill('muet', 'muet', scount.muet)}` +
    `<a class="capsum-link" href="#freshness-view" title="Détail par feed (santé de collecte) : Données → Fraîcheur">voir le détail →</a></div>`;
}

// exports du module Fraîcheur/Intégrations (importés par app.js : refresh() + bouton #fresh-refresh).
export { renderIntegrations, renderFreshness, renderFreshnessPulse };

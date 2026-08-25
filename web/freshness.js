// freshness.js — panneaux « Fraîcheur (santé par source) » + « Intégrations (couverture capteurs/hôtes) »
// de la Vue d'ensemble, extraits d'app.js (1re découpe par CONCERN). Comportement
// IDENTIQUE au monolithe : fonctions simplement relocalisées, aucune logique modifiée. Dépend uniquement de
// core.js (helpers DOM/api/esc/ic), state.js (S : freshnessRepollTimer/freshCollapsed) et d'UN export d'app.js
// (setAlertSourceFilter, pour le pivot cloche « source chaude » -> alertes filtrées). Le cycle app<->freshness
// est sans danger : setAlertSourceFilter n'est appelé qu'à l'EXÉCUTION (clic), jamais à l'évaluation du module.
// collapsibleGroup vit dans core.js (helper PARTAGÉ règles/parseurs/actions/playbooks) ; il n'est pas un
// membre du concern Fraîcheur (que renderFreshness/renderIntegrations n'appellent pas) — d'où non importé ici.
import { $, api, esc, fmtTs, ic, LANG } from './core.js';
import { S } from './state.js';
import { setAlertSourceFilter } from './app.js';

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// P11.16-b — LA FAMILLE D'UN NOMBRE EST DÉCLARÉE, ET C'EST ELLE QUI CHOISIT LE SIGNE.
//
// CE QUI N'ÉTAIT PAS LE DÉFAUT. Relevé en usage réel le 2026-08-25 : l'exploitant lit la rangée de
// vignettes et conclut que « cela ne concorde pas ». AUCUN CHIFFRE N'EST FAUX, et les deux
// répartitions de cette surface tiennent PAR CONSTRUCTION — le démon incrémente le total une fois par
// alerte puis exactement une branche sur trois ; `countStates` range chaque flux dans l'un de cinq
// états, repli compris, donc la somme des états vaut le nombre de flux. Le défaut est de PRÉSENTATION.
//
// CE QU'IL ÉTAIT. La rangée posait, sous des jetons IDENTIQUES, des nombres qui se PARTAGENT un total
// et un nombre qui RECOUPE la même population sans la partager — déjà compté dans une part. Un lecteur
// qui additionne la rangée dépasse le total, et il a raison de s'en étonner. Le code le SAVAIT et
// l'écrivait en commentaire (« un compte à part, pas un état ») ; l'écran, lui, ne le disait pas :
// c'est la famille de défaut que ce dépôt poursuit — la connaissance existe et n'atteint pas le lecteur.
//
// LA FABRIQUE, PAS LE CAS PARTICULIER. Un cas spécial posé sur le sixième nombre aurait déplacé le
// problème d'un cran : le septième en aurait hérité. Chaque nombre DÉCLARE donc sa famille, et la
// famille choisit le signe qui le relie à ses voisins :
//   `total`       — le nombre que la répartition partage ; il ouvre la rangée.
//   `part`        — un terme de ce partage ; « = » après le total, « + » entre parts : la rangée se
//                   recompose à l'œil, sans lire une explication.
//   `recoupement` — un compte pris sur la MÊME population sans la partager ; introduit par « dont »,
//                   donc visiblement hors de l'addition.
// Un nombre qui ne déclare aucune de ces familles n'hérite PAS du jeton par défaut : il est rendu avec
// l'aveu que sa famille manque. C'est le seul état que cette fabrique refuse de taire — et c'est ce qui
// oblige le prochain nombre ajouté à se déclarer au lieu de se fondre dans la rangée.
//
// AUCUNE VIGNETTE N'EST RETIRÉE PARCE QU'ELLE VAUT ZÉRO. Un terme qui disparaît à zéro ne se distingue
// plus d'un terme qui n'existe pas, et la répartition cesse de se recomposer. Un zéro est rendu en
// atténué : présent pour l'addition, sans tirer le regard.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const FAMILLES_DE_CHIFFRE = ['total', 'part', 'recoupement'];
// « dont » : le mot qui dit un SOUS-ENSEMBLE. Il porte à lui seul la distinction que la rangée taisait.
const MOT_DONT = LANG === 'en' ? 'of which' : 'dont';
// LE SIGNE QUI RELIE une vignette à celle qui la précède — dérivé du COUPLE de familles, jamais écrit
// sur une vignette en particulier. Une part qui suit un recoupement, ou une famille non déclarée,
// retombe sur le point médian : aucune addition n'est promise là où elle ne serait pas vraie.
function signeEntreChiffres(famille, precedente) {
  if (!precedente) return '';
  if (famille === 'recoupement') return '· ' + MOT_DONT;
  if (famille === 'part') return precedente === 'total' ? '=' : precedente === 'part' ? '+' : '·';
  return '·';
}
// UNE VIGNETTE : { famille, valeur, libelle, dot?, cloche?, titre?, suite? }. `suite` est un fragment
// HTML DÉJÀ échappé par l'appelant (la liste des noms d'un compte), rendu DANS la vignette pour que les
// signes restent collés aux nombres qu'ils relient.
function vignetteDeChiffre(c, famille) {
  const zero = !Number(c.valeur);
  const dot = c.dot ? `<span class="fdot ${c.dot}"></span>` : '';
  const nombre = famille === 'total' ? `<b>${c.valeur}</b>&nbsp;`
    : c.cloche ? `<span class="fhot">${ic('bell')} ${c.valeur}</span> `
    : `${c.valeur} `;
  const aveu = famille === 'indeclaree'
    ? ` <span style="color:var(--warn)">(${LANG === 'en' ? 'family not declared' : 'famille non déclarée'})</span>` : '';
  return `<span class="capsum-pill"${zero ? ' style="color:var(--mut)"' : ''}${c.titre ? ` title="${esc(c.titre)}"` : ''}>` +
    `${dot}${nombre}${esc(c.libelle)}${c.suite || ''}${aveu}</span>`;
}
// LA RANGÉE — seule entrée de la fabrique, partagée par les deux panneaux de cette surface.
function rangeeDeChiffres(chiffres) {
  let html = '', precedente = '';
  for (const c of chiffres) {
    const famille = FAMILLES_DE_CHIFFRE.includes(c.famille) ? c.famille : 'indeclaree';
    const signe = signeEntreChiffres(famille, precedente);
    if (signe) html += `<span style="color:var(--mut)">${signe}</span>`;
    html += vignetteDeChiffre(c, famille);
    precedente = famille;
  }
  return html;
}

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
  // INDIVIDUELLEMENT passe 'muet' (>3x son intervalle) MÊME si le pipeline global reste frais. Fraîcheur rend la
  // même observation « en retard » (P11.3-b, même seuil, dérivé de la même sonde). On garde une pastille muet
  // ROUGE ici : on ne réduit pas la visibilité (invariant opérateur). Compteurs additifs : déclarés = branchés +
  // muets + en attente.
  const mute = collectors.filter(c => c.status === 'muet');
  const total = collectors.length, connected = total - waiting.length - mute.length;
  // les noms tiennent DANS la vignette du compte qu'ils détaillent (P11.16-b) : hors d'elle, ils se
  // seraient glissés entre un nombre et le signe qui le relie au suivant.
  const withNames = (arr) => { const nm = arr.map(c => esc(c.label || c.id)).join(', '); return nm ? ` <span style="font-size:11px;color:var(--mut)">(${nm})</span>` : ''; };
  // « branché(s) » = pastille NEUTRE (pas de couleur santé) : c'est de la COUVERTURE, pas de la fraîcheur
  // (le vert=frais reste réservé à Fraîcheur) -> l'opérateur ne confond plus les deux compteurs.
  // muet : capteur branché puis décroché (dead-man's-switch continu). ROUGE = alerte : à investiguer.
  // en attente : sondes déclarées-jamais-vues, nommées inline (YARA EST le en_attente data-driven -> sa
  // vignette retombe à zéro d'elle-même dès qu'un event source=yara arrive).
  // P3.2-a — LA PORTÉE D'UNE SONDE SE LIT, ELLE NE SE DEVINE PAS. Une sonde « tous hôtes confondus »
  // rend la donnée la plus FRAÎCHE du parc : elle reste verte tant qu'UNE machine parle encore. Le champ
  // `portee` vient du serveur (dérivé du type de la sonde) — on le COMPTE ici plutôt que de le déduire
  // d'une liste locale, qui aurait dérivé du jour où une sonde change de portée.
  const confondues = collectors.filter(c => c.portee === 'tous hôtes confondus').length;
  // P11.16-b — CETTE RANGÉE PORTAIT LE MÊME DÉFAUT que celle de Fraîcheur, et elle est réparée par la
  // MÊME fabrique : « déclarés = branchés + muets + en attente » se lisait déjà en commentaire ici, et
  // la portée « tous hôtes confondus » RECOUPE ces trois parts (une sonde de cette portée est déjà
  // comptée dans son état) sans jamais les partager.
  const capsum = `<div class="capsum">` + rangeeDeChiffres([
    { famille: 'total', valeur: total, libelle: LANG === 'en' ? 'declared sensors' : 'capteurs déclarés',
      titre: LANG === 'en' ? 'A sensor is a PROBE TYPE, not a source: the total is shared by the three terms joined by « + ». What follows « of which » is taken from the same population and is not part of the addition.' : 'Un capteur est un TYPE de sonde, pas une source : le total se partage entre les trois termes reliés par « + ». Ce qui suit « dont » est pris sur la même population et n\'entre pas dans l\'addition.' },
    { famille: 'part', valeur: connected, libelle: LANG === 'en' ? 'connected' : 'branché(s)',
      titre: LANG === 'en' ? 'Declared sensors that have already reported at least one piece of data.' : 'Capteurs déclarés ayant déjà remonté au moins une donnée.' },
    { famille: 'part', valeur: mute.length, dot: 'muet', libelle: LANG === 'en' ? 'mute' : 'muet(s)', suite: withNames(mute),
      titre: LANG === 'en' ? 'Connected then dropped out (continuous dead-man\'s-switch): to investigate.' : 'Branché puis décroché (dead-man\'s-switch continu) : à investiguer.' },
    { famille: 'part', valeur: waiting.length, dot: 'attente', libelle: LANG === 'en' ? 'waiting' : 'en attente', suite: withNames(waiting),
      titre: LANG === 'en' ? 'Declared, never seen: no data yet from this probe.' : 'Déclaré, jamais vu : aucune donnée de cette sonde à ce jour.' },
    { famille: 'recoupement', valeur: confondues, libelle: LANG === 'en' ? 'at « all hosts together » scope' : 'à portée « tous hôtes confondus »',
      titre: LANG === 'en' ? 'ALREADY counted in one of the terms above — this number crosses the distribution, it does not share it. These probes return the FRESHEST data of the estate: they stay green as long as a single machine still talks. Fully silent machines are counted separately (Hosts).' : 'DÉJÀ comptées dans l\'un des termes ci-dessus — ce nombre recoupe la répartition, il ne la partage pas. Ces sondes rendent la donnée la plus FRAÎCHE du parc : elles restent vertes tant qu\'une seule machine parle encore. Les machines entièrement muettes sont comptées à part (Hôtes).' },
  ]) +
    `<a class="capsum-link" href="#freshness-view" title="Santé par source (frais/calme/en retard/muet) : Données → Fraîcheur">santé des sources →</a>` +
    `<a class="capsum-link" href="#sources" title="Inventaire complet des sources (Données → Sources)">inventaire →</a></div>`;
  const hosts = (d.hosts || []).length
    ? d.hosts.map(h => `<div class="kv"><span>${ic('server')} ${esc(h.host)}</span><span class="muted">${fmtTs(h.last_seen)}</span></div>`).join('')
    : '<div class="muted">hôte local uniquement — aucun agent distant n\'a encore poussé de logs.</div>';
  // P3.2-a — LE COMPTE D'HÔTES MUETS, seul chiffre de ce panneau qui parle des machines qui se sont tues
  // (les sondes ci-dessus ne le peuvent pas : leur portée les en empêche). `flotte` absent/null = la
  // lecture de l'inventaire a échoué -> on l'ÉCRIT au lieu d'afficher un zéro rassurant.
  // P11.10-a — LA PART DÉCLARÉE EST DITE. Un compte qui rétrécit sans dire pourquoi se lit comme une
  // amélioration ; « aucun muet » là où des machines muettes ont simplement été déclarées telles serait
  // faux. La phrase porte donc le compte hors-alerte quand il existe, et rien quand il n'existe pas.
  const fl = d.flotte;
  const declares = fl && fl.muets_declares_attendus
    ? ` <span class="muted fldeclares">(+ ${fl.muets_declares_attendus} muet(s) au silence déclaré attendu, hors alerte)</span>`
    : '';
  const flotteLigne = fl === undefined ? ''
    : fl === null ? '<div class="kv"><span class="muted">hôtes muets : inventaire illisible (aucun verdict rendu)</span></div>'
    : fl.muets > 0
      ? `<div class="kv"><span class="fdot muet"></span><span><b>${fl.muets}</b> hôte(s) muet(s) sur ${fl.attendus} — aucun signal depuis plus de ${Math.round(fl.seuil_s / 60)} min${declares}</span></div>`
      : `<div class="kv"><span class="muted">${fl.attendus} hôte(s) inventoriés, aucun muet non déclaré${declares}</span></div>`;
  // caption : sépare EXPLICITEMENT les 2 axes (couverture de sondes vs endpoints) et renvoie la SANTÉ à Fraîcheur.
  const cap = `<div class="muted intplug" style="font-size:11px">Capteurs = <b>couverture</b> (types de sondes déclarés ; un capteur mort est signalé <b>muet</b> ici) · Hôtes = <b>endpoints</b> (où les agents poussent). La santé fine par source (frais/calme/en retard/muet) vit dans Fraîcheur — « en retard » y désigne la même observation que « muet » ici, au même seuil.</div>`;
  // lien de découverte -> la Flotte (inventaire détaillé des hôtes : statut/enrôlement/dernier signal, paginé + export).
  const hostsHdr = `Hôtes (endpoints) <a class="capsum-link" href="#fleet" title="Flotte d'agents : inventaire détaillé (statut, enrôlement, dernier signal) — Données → Flotte">flotte →</a>`;
  b.innerHTML = `<div class="intgrid"><div><div class="fldname">Capteurs (couverture)</div>${capsum}</div><div><div class="fldname">${hostsHdr}</div>${flotteLigne}${hosts}</div></div>${cap}`;
}
// fraîcheur PAR SOURCE : âge du dernier point + statut. « Est-ce live ? »
/* state: freshnessRepollTimer -> S (state.js) */   // re-poll rapproché quand le serveur calcule encore (warming)
// état de pliage persisté (l'auto-refresh re-rend le panneau -> on ne ré-ouvre pas à chaque tick).
// Clé unique 'metric-open' = les séries métriques sont dépliées.
// Par défaut (1re visite, clé absente) on ne replie QUE le groupe « calme » (sources peu actives, OK).
/* state: freshCollapsed -> S (state.js) */
//
// P11.3-b — LE STATUT VIENT DU DÉMON, ET IL N'Y A PLUS DE « DÉGRADÉ ». Cette surface fabriquait un
// quatrième mot (« dégradé / en retard ») à partir de deux choses sans rapport : des alertes actives, ou un
// âge supérieur à 4× un intervalle `expected_s` qui n'était pas une cadence attendue mais la moyenne
// observée sur 24 h. Le démon rend désormais UN statut dérivé de la cadence DÉCLARÉE par la sonde
// (`statut_de_source`) : muet (plus rien n'arrive, toutes sources) > en_retard (cadence déclarée continue
// dépassée) > frais (< 15 min) > calme (collecte saine, source peu active). Les alertes actives restent
// un COMPTE (cloche) à côté du statut, jamais un statut. `attente` (déclaré, jamais de donnée) ne concerne
// que les capteurs d'Intégrations (les feeds de /freshness ont tous une donnée).
const FSTATES = ['muet', 'en_retard', 'attente', 'frais', 'calme'];
function freshState(f) {
  const s = f.status === 'inconnu' || f.status === 'en_attente' ? 'attente' : f.status;
  return FSTATES.includes(s) ? s : 'calme';
}
// pastille (.fdot) par état — `en_retard` reprend la pastille orange existante.
const FSTATE_DOT = { muet: 'muet', en_retard: 'warn', attente: 'attente', frais: 'frais', calme: 'calme' };
// classe de couleur du texte (le <b> "il y a …") par état
const FSTATE_TXT = { muet: 'bad', en_retard: 'fwarn', frais: 'ok', calme: 'calm', attente: 'mut' };
// libellé d'en-tête de groupe quand on regroupe PAR ÉTAT
const FSTATE_LBL = { muet: 'muet — plus rien n\'arrive, toutes sources confondues', en_retard: 'en retard — cadence déclarée dépassée', attente: 'en attente — déclaré, pas encore de donnée', frais: 'frais (donnée < 15 min)', calme: 'calme (collecte saine, source peu active)' };
const SRANK = { muet: 0, en_retard: 1, attente: 2, frais: 3, calme: 4 };   // panne en haut ; puis en retard, en attente, frais, calme
const age = s => s < 90 ? s + ' s' : s < 5400 ? Math.round(s / 60) + ' min' : s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' j';
// libellé de la cadence DÉCLARÉE d'un feed — par une sonde du démon OU par l'exploitant (P11.3-c) ; le
// rythme observé est rendu à part (title). « aucune cadence déclarée » n'est pas un défaut : c'est un blanc.
function cadenceLabel(f) {
  if (f.cadence_declaree === 'continue') return 'continu' + (f.cadence_interval_s ? ' · ' + age(f.cadence_interval_s) : '');
  if (f.cadence_declaree === 'evenementielle') return 'événementiel — pas de cadence par nature';
  return 'aucune cadence déclarée';
}
function cadenceTitle(f) {
  const decl = f.cadence_capteur ? 'cadence déclarée par la sonde « ' + f.cadence_capteur + ' »'
    : f.cadence_par ? 'cadence déclarée par ' + f.cadence_par + (f.cadence_le ? ' le ' + fmtTs(f.cadence_le) : '')
    : 'personne n\'a déclaré de cadence pour cette source — ni une sonde du démon, ni l\'exploitant : l\'âge ne dit que l\'activité, et elle ne peut pas être « en retard »';
  return decl + (f.observed_interval_s ? ' · rythme observé sur 24 h : ~1 donnée / ' + age(f.observed_interval_s) : '');
}
// compteurs par état + alertes actives (un compte à part, pas un état) — même agrégation pour le détail et le
// pulse. LES CINQ ÉTATS SE PARTAGENT `feeds.length` PAR CONSTRUCTION : `freshState` a un repli, donc chaque
// flux incrémente exactement un état. `alertes` compte sur la MÊME population sans la partager — c'est ce que
// la rangée DIT désormais (« dont »), au lieu de le laisser dans ce commentaire (P11.16-b).
function countStates(feeds) {
  const scount = { muet: 0, en_retard: 0, attente: 0, frais: 0, calme: 0, alertes: 0 };
  feeds.forEach(f => { scount[freshState(f)] += 1; if (Number(f.active_alerts) > 0) scount.alertes += 1; });
  return scount;
}
// LE LIBELLÉ COURT D'UN ÉTAT, DÉRIVÉ du libellé long des groupes : la vignette, l'en-tête de groupe et
// la légende ne peuvent plus diverger, et ajouter un état n'oblige pas à écrire son mot deux fois. Le
// long porte la définition (« — … » ou « (…) »), le court en est le premier segment ; sans séparateur,
// c'est le libellé entier qui est rendu — trop long dans la rangée, donc VISIBLE, jamais silencieux.
const libelleCourtDEtat = (etat) => String(FSTATE_LBL[etat] || etat).split(/ [—(]/)[0].trim();
// L'ORDRE DE LECTURE des parts : du plus sain au plus grave, l'inverse exact du rang de tri du détail
// (`SRANK`, la panne en haut). Une seule table de rang, lue dans les deux sens — pas une seconde liste.
const ETATS_DE_LA_RANGEE = [...FSTATES].sort((a, b) => (SRANK[b] ?? 9) - (SRANK[a] ?? 9));
// LA RANGÉE DE FRAÎCHEUR, déclarée famille par famille (cf. la fabrique en tête de module) : cinq parts
// qui se partagent le total, et UN recoupement — les flux porteurs d'alertes actives, déjà comptés dans
// leur état, que l'addition ne doit pas reprendre.
function summaryPills(feeds) {
  const sc = countStates(feeds);
  return rangeeDeChiffres([
    { famille: 'total', valeur: feeds.length, libelle: LANG === 'en' ? 'feed(s) observed' : 'feed(s) observé(s)',
      titre: LANG === 'en' ? 'The row recomposes: the total is the sum of the terms joined by « + ». What follows « of which » is taken from the same population and is not part of the addition.' : 'La rangée se recompose : le total est la somme des termes reliés par « + ». Ce qui suit « dont » est pris sur la même population et n\'entre pas dans l\'addition.' },
    ...ETATS_DE_LA_RANGEE.map(e => ({ famille: 'part', valeur: sc[e], dot: FSTATE_DOT[e], libelle: libelleCourtDEtat(e), titre: FSTATE_LBL[e] })),
    { famille: 'recoupement', valeur: sc.alertes, cloche: true, libelle: LANG === 'en' ? 'with active alerts' : 'avec alertes actives',
      titre: LANG === 'en' ? 'These feeds are ALREADY counted in their state above: this number crosses the distribution, it does not share it — adding it in would exceed the total. An active alert is a count, never a collection state.' : 'Ces flux sont DÉJÀ comptés dans leur état ci-dessus : ce nombre recoupe la répartition, il ne la partage pas — l\'additionner ferait dépasser le total. Une alerte active est un compte, jamais un état de collecte.' },
  ]);
}

// RENDU PUR du détail à partir de la charge utile de /api/freshness (exercé par le harnais ESM sur des objets
// fabriqués). Renvoie le HTML ; `renderFreshness` le pose et câble les gestes.
function renderFreshnessDetail(d) {
  const feeds = (d.feeds || []).slice();
  feeds.sort((a, c) => ((SRANK[freshState(a)] ?? 9) - (SRANK[freshState(c)] ?? 9)) || a.name.localeCompare(c.name));
  // le STATUT = santé de collecte : muet seulement si l'ingestion est en panne ; en retard seulement au-delà
  // d'une cadence DÉCLARÉE ; sinon l'âge est INFORMATIF.
  const head0 = !d.pipeline_fresh
    ? `<div class="bad" style="font-weight:600;margin-bottom:8px">${ic('warn')} Ingestion en panne — aucune donnée reçue récemment</div>`
    : `<div class="muted" style="margin-bottom:8px">Collecte OK. L'âge = temps depuis la dernière donnée. Il ne devient un retard que pour une source dont QUELQU'UN — une sonde du démon ou l'exploitant — DÉCLARE une cadence continue ; pour les autres, il ne dit que l'activité.</div>`;
  // P11.3-d — CE QUE LA CLOCHE COUVRE, ET CE QU'ELLE NE COUVRE PAS.
  //
  // L'ancienne phrase (« N alerte(s) active(s) sans source déterminée — aucune cloche de source ne les
  // porte ») disait un fait vrai d'une façon qui se lisait comme un défaut de collecte : elle ne disait ni
  // ce qu'est une cloche, ni que la plupart des alertes qu'elle désigne n'ont AUCUNE raison d'avoir un
  // flux (une alerte d'hôte, de règle éteinte ou de seuil ne parle pas d'un flux). Et elle ignorait une
  // troisième famille, mesurée le 2026-08-23 : les alertes dont l'imputation n'a jamais été enregistrée,
  // que le compte par source laisse tomber en silence.
  //
  // LE BLOC N'EST RENDU QUE S'IL DIT QUELQUE CHOSE DE VRAI : sans alerte active, il n'y a rien à répartir
  // et rien ne s'affiche. Il est NEUTRE (muted), jamais orange : ce n'est pas une anomalie, c'est une
  // répartition — les quatre nombres se retrouvent, ce qui est précisément ce qu'un lecteur doit pouvoir
  // vérifier. Charge utile absente (démon antérieur) -> rien, jamais une ligne fantôme.
  const imp = d.imputation_des_alertes || null;
  const orph = imp ? Number(imp.sans_source_nommee) || 0 : 0;
  const muettes = imp ? Number(imp.sans_imputation) || 0 : 0;
  const actives = imp ? Number(imp.actives) || 0 : 0;
  let bloc = '';
  if (imp && actives > 0) {
    const jeton = String(imp.jeton_sans_source || '');
    const parts = [`${ic('bell')} <b>${actives}</b> alerte(s) active(s) : <b>${Number(imp.avec_cloche) || 0}</b> imputée(s) à un flux (leur cloche est allumée ci-dessous)`];
    if (orph > 0) {
      parts.push(`<b>${orph}</b> <span class="forph" role="button" tabindex="0" data-src="${esc(jeton)}" title="Ces alertes DISENT qu'elles ne se rapportent à aucun flux : une alerte d'hôte, de règle ou de seuil n'en a pas. Ce n'est pas un défaut de collecte. Cliquer pour les voir.">sans flux (normal pour une alerte d'hôte, de règle ou de seuil)</span>`);
    }
    if (muettes > 0) {
      parts.push(`<b>${muettes}</b> <span title="Aucune imputation enregistrée et rien de nommable dans leur texte : alertes levées avant l'imputation, ou par un producteur qui ne l'écrit pas. Le compte par source les ignore — c'est dit ici plutôt que tu.">sans imputation enregistrée (le compte par source les ignore)</span>`);
    }
    bloc = `<div class="muted fimput" style="margin-bottom:8px">${parts.join(' · ')}. Une cloche compte les alertes imputées à UNE source, toutes dates — elle ne dit rien de sa fraîcheur.</div>`;
  }
  const head = head0 + bloc;
  // une SÉRIE métrique (sous le feed agrégé déplié) : même modèle d'état que les sources (statut du démon).
  const seriesRow = s => {
    const ss = freshState(s);
    return `<div class="kv fseries"><span><span class="fdot ${FSTATE_DOT[ss]}"></span>${esc(s.name)}</span>` +
      `<b class="${FSTATE_TXT[ss] || 'bad'}" title="dernière donnée ${fmtTs(s.last_seen)}">il y a ${age(s.age_s)}</b></div>`;
  };
  // une ligne par source ; surlignée (classe .hot + cloche) si la source a des alertes actives (active_alerts>0).
  const rowOf = f => {
    const st = freshState(f);
    if (f.kind === 'metric') {
      const sList = f.series || [];
      const open = S.freshCollapsed.has('metric-open');
      const body = sList.length
        ? `<div class="fmetricbody">${sList.map(seriesRow).join('')}</div>`
        : `<div class="fmetricbody muted" style="padding:4px 0 0 18px">détail des séries indisponible (mettre à jour le daemon)</div>`;
      const hd = `<div class="kv fmetrichd" role="button" tabindex="0" aria-expanded="${open ? 'true' : 'false'}" title="Plier / déplier les séries métriques">` +
        `<span><span class="fchev">${ic('chevright')}</span><span class="fdot ${FSTATE_DOT[st]}"></span>${esc(f.name)} <span class="muted fkind" title="${esc(cadenceTitle(f))}">${esc(cadenceLabel(f))}</span></span>` +
        `<b class="${FSTATE_TXT[st] || 'bad'}">il y a ${age(f.age_s)}</b></div>`;
      return `<div class="fmetric${open ? '' : ' collapsed'}">${hd}${body}</div>`;
    }
    const hot = Number(f.active_alerts) > 0;
    const badge = hot ? ` <span class="fhot" role="button" tabindex="0" data-src="${esc(f.name)}" title="${f.active_alerts} alerte(s) non acquittée(s) imputée(s) à ${esc(f.name)}, toutes dates (cases comprises) — un compte, sans lien avec sa fraîcheur · cliquer pour les voir">${ic('bell')} ${f.active_alerts}</span>` : '';
    // « en retard » : la raison est DITE sur la ligne (cadence déclarée, sonde, silence), pas seulement coloriée.
    const reason = st === 'en_retard'
      ? `en retard — aucune donnée depuis ${age(f.age_s)} pour une cadence déclarée de ${age(f.cadence_interval_s || 0)} (sonde « ${f.cadence_capteur || '?'} »)`
      : '';
    const why = reason ? ` <span class="muted fwhy">· au-delà de ${age(f.cadence_interval_s || 0)}</span>` : '';
    return `<div class="kv${hot ? ' hot' : ''}"${reason ? ` title="${esc(reason)}"` : ''}><span><span class="fdot ${FSTATE_DOT[st]}"></span>${esc(f.name)} <span class="muted fkind" title="${esc(cadenceTitle(f))}">${esc(cadenceLabel(f))}</span>${badge}${why}</span>` +
      `<b class="${FSTATE_TXT[st] || 'bad'}" title="dernière donnée ${fmtTs(f.last_seen)}">il y a ${age(f.age_s)}</b></div>`;
  };
  // GROUPES PAR ÉTAT : chaque état est une section repliable (libellé + nombre + pastille), tri DANS le groupe
  // le plus PÉRIMÉ d'abord (age décroissant). Par défaut seul « calme » est replié (voir init de
  // freshCollapsed). État persisté dans freshCollapsed (clé 'cat:<état>' présente = REPLIÉ).
  const groups = new Map();
  feeds.forEach(f => { const c = freshState(f); if (!groups.has(c)) groups.set(c, []); groups.get(c).push(f); });
  const cats = [...groups.entries()].sort((a, c) => (SRANK[a[0]] ?? 9) - (SRANK[c[0]] ?? 9));
  const summaryLine = `<div class="capsum">${summaryPills(feeds)}` +
    `<a class="capsum-link" href="#sources" title="Ouvrir l'inventaire complet des sources (Données → Sources)">voir l'inventaire →</a></div>`;
  let html = head + summaryLine;
  for (const [cat, arr] of cats) {
    arr.sort((a, c) => (c.age_s - a.age_s) || a.name.localeCompare(c.name));
    const collapsed = S.freshCollapsed.has('cat:' + cat);
    const lbl = FSTATE_LBL[cat] || cat;
    html += `<div class="fgroup${collapsed ? ' collapsed' : ''}" data-cat="${esc(cat)}">` +
      `<button type="button" class="fgrouphd" aria-expanded="${collapsed ? 'false' : 'true'}" title="Plier / déplier ${esc(lbl)}">` +
      `${ic('chevdown')}<span class="fdot ${FSTATE_DOT[cat]}"></span><span class="fglbl">${esc(lbl)}</span><span class="fgcount">${arr.length}</span></button>` +
      `<div class="fgbody">${arr.map(rowOf).join('')}</div></div>`;
  }
  html += `<div class="flegend"><span class="fdot frais"></span>frais (donnée &lt; 15 min) · <span class="fdot calme"></span>calme (collecte saine, source peu active) · <span class="fdot warn"></span>en retard (cadence déclarée dépassée) · <span class="fdot attente"></span>en attente (déclaré, pas de donnée) · <span class="fdot muet"></span>muet (plus rien n'arrive, toutes sources confondues)` +
    `<div class="muted" style="margin-top:4px">La cadence attendue est celle qu'une sonde du démon ou l'exploitant DÉCLARE (affichée à côté du nom, avec son déclarant au survol). Une source événementielle, ou dont personne n'a déclaré la cadence, n'est jamais « en retard » : son âge ne dit que son activité, et ce blanc n'est pas un défaut — il se comble depuis l'Inventaire (Données → Sources). Les alertes actives sont un compte (cloche), pas un état de collecte.</div>` +
    // P11.16-a — CE PANNEAU NE PEUT PAS NOMMER LE PRODUCTEUR : la charge utile de `/api/freshness` ne
    // porte que le NOM de la source (le rapprochement dérivé vit dans `/api/sources`). Plutôt que de
    // laisser croire qu'un nom de flux nomme le fichier qui l'émet, la légende dit où ce nom se trouve.
    // Phrase posée dans son PROPRE nœud : ajoutée au texte ci-dessus, elle l'aurait rendu intraduisible.
    `<div class="muted" style="margin-top:4px">${LANG === 'en' ? 'A feed\'s name is the name of the SOURCE, not of the file that emits it — the two often differ. The producer of each source is named in the inventory (Data → Sources).' : 'Le nom d\'un flux est celui de la SOURCE, pas du fichier qui l\'émet — les deux diffèrent souvent. Le producteur de chaque source est nommé dans l\'inventaire (Données → Sources).'}</div></div>`;
  return html;
}
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
  const html = renderFreshnessDetail(d);
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
  // FIX 2 / P11.3-d — cloche d'une source « chaude » cliquable -> alertes filtrées par CETTE source
  // (#notifications). Le compte « sans flux » pivote de la même façon, sur le JETON que le démon publie
  // (`jeton_sans_source`) : la console ne réécrit pas ce nom en dur, elle pose la facette que le démon
  // sait apparier — les alertes visées sont donc exactement celles que ce compte annonce.
  b.querySelectorAll('.fhot[data-src], .forph[data-src]').forEach(el => {
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
// (N feeds / frais / calme / en retard / en attente / muet / avec alertes) + un lien « voir le détail → » vers l'onglet
// Données → Fraîcheur (#freshness-view). PAS de drilldown par feed ici (il vit dans #freshness-panel, via
// renderFreshness). Réutilise EXACTEMENT la même agrégation (summaryPills) que le détail.
async function renderFreshnessPulse() {
  const b = $('#freshness .body'); if (!b) return;
  let d; try { d = await api('/freshness'); } catch (e) { return; }
  const feeds = d.feeds || [];
  if (d.warming && !feeds.length) { b.innerHTML = '<div class="muted">… mesure de la fraîcheur des sources en cours</div>'; return; }
  if (!feeds.length) { b.innerHTML = '<div class="muted">aucun feed récent</div>'; return; }
  const head = !d.pipeline_fresh
    ? `<div class="bad" style="font-weight:600;margin-bottom:8px">${ic('warn')} Ingestion en panne — aucune donnée reçue récemment</div>`
    : '';
  b.innerHTML = head +
    `<div class="capsum">${summaryPills(feeds)}` +
    `<a class="capsum-link" href="#freshness-view" title="Détail par feed (santé de collecte) : Données → Fraîcheur">voir le détail →</a></div>`;
}

// exports du module Fraîcheur/Intégrations (importés par app.js : refresh() + bouton #fresh-refresh).
export { renderIntegrations, renderFreshness, renderFreshnessPulse, renderFreshnessDetail, freshState, countStates };

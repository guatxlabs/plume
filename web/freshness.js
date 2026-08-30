// freshness.js — panneaux « Fraîcheur (santé par source) » + « Intégrations (couverture capteurs/hôtes) »
// de la Vue d'ensemble, extraits d'app.js (1re découpe par CONCERN). Comportement
// IDENTIQUE au monolithe : fonctions simplement relocalisées, aucune logique modifiée. Dépend uniquement de
// core.js (helpers DOM/api/esc/ic), state.js (S : freshnessRepollTimer/freshCollapsed) et d'UN export d'app.js
// (setAlertSourceFilter, pour le pivot cloche « source chaude » -> alertes filtrées). Le cycle app<->freshness
// est sans danger : setAlertSourceFilter n'est appelé qu'à l'EXÉCUTION (clic), jamais à l'évaluation du module.
// collapsibleGroup vit dans core.js (helper PARTAGÉ règles/parseurs/actions/playbooks) ; il n'est pas un
// membre du concern Fraîcheur (que renderFreshness/renderIntegrations n'appellent pas) — d'où non importé ici.
//
// TROIS EMPRUNTS, AUCUNE RECOPIE (`P11.18-f`, `P11.18-g`) : le VOCABULAIRE d'état d'une source vient de
// `sources.js` (il y est canonique et l'inventaire le pose déjà) ; le COMPARATEUR de tri vient de
// `core.js`, c'est celui du tri par colonne des listes partagées, qui MESURE le type des valeurs au lieu
// de le supposer ; la MÉMOIRE d'un choix d'affichage vient de `prefs.js`. Le sens des imports va de
// freshness vers sources, jamais l'inverse : sources.js ne dépend que de core.js, donc aucun cycle neuf
// n'est introduit (celui qui existe, app<->freshness, reste le seul, et il est sans danger — cf. plus haut).
import { $, api, colComparator, disclosure, esc, fmtTs, ic, LANG } from './core.js';
import { S } from './state.js';
import { setAlertSourceFilter } from './app.js';
import { ETAT_DE_SOURCE, etatDeSource, rangDEtatDeSource } from './sources.js';
import { prefGet, prefSet } from './prefs.js';

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

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// `P11.18-e` — DEUX LIBELLÉS NE DÉSIGNENT JAMAIS LA MÊME DESTINATION.
//
// LE CONSTAT, ET CE QU'IL COÛTE. Cette surface offrait « santé des sources → » et « voir le détail → »
// qui mènent au MÊME onglet, et « inventaire → » et « voir l'inventaire → » qui mènent au même autre.
// Deux noms font croire à deux endroits : l'exploitant qui a suivi les deux cherche ensuite ce qu'il a
// manqué, et il n'y a rien à trouver. Le nom d'un renvoi ne dit pas ce qu'on fait en cliquant, il dit
// CE QU'ON TROUVE À L'ARRIVÉE — donc le nom que porte la destination elle-même.
//
// LA PROPRIÉTÉ EST TENUE PAR CONSTRUCTION, PAS PAR RELECTURE. Corriger la paire signalée aurait laissé
// la suivante s'écrire. Le libellé n'est donc plus écrit sur le renvoi : il est DÉRIVÉ de la
// destination par cette table, seule source des renvois de ce module. Écrire deux noms pour une même
// ancre est devenu impossible — il n'y a plus qu'un endroit où un nom s'écrit.
//
// UNE DESTINATION QUE LA TABLE NE NOMME PAS N'EST PAS RENDUE EN SILENCE : le renvoi avoue qu'elle n'est
// pas nommée, comme la fabrique de chiffres avoue une famille manquante (`P11.16-b`). C'est ce qui
// oblige le prochain renvoi à se déclarer au lieu de se fondre dans la surface.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const RENVOIS = {
  '#freshness-view': {
    nom: LANG === 'en' ? 'Source freshness' : 'Fraîcheur des sources',
    titre: LANG === 'en' ? 'Collection health per feed, grouped by state (fresh / quiet / late / waiting / mute): Data → Source freshness.' : 'Santé de collecte par flux, groupée par état (frais / calme / en retard / en attente / muet) : Données → Fraîcheur des sources.',
  },
  '#sources': {
    nom: LANG === 'en' ? 'Source inventory' : 'Inventaire des sources',
    titre: LANG === 'en' ? 'Every ingestion source, its producer, its declarer, its declared cadence and its display metadata: Data → Sources.' : 'Toutes les sources d\'ingestion, leur producteur, leur déclarant, leur cadence déclarée et leurs métadonnées d\'affichage : Données → Sources.',
  },
  '#fleet': {
    nom: LANG === 'en' ? 'Fleet' : 'Flotte',
    titre: LANG === 'en' ? 'Host inventory: status, enrolment, last signal — Data → Fleet.' : 'Inventaire des hôtes : statut, enrôlement, dernier signal — Données → Flotte.',
  },
  '#alerts': {
    nom: LANG === 'en' ? 'Alerts' : 'Alertes',
    titre: LANG === 'en' ? 'What has been DETECTED, all sources together, with its own filters and facets: Cases → Alerts.' : 'Ce qui a été DÉTECTÉ, toutes sources confondues, avec ses propres filtres et facettes : Cas → Alertes.',
  },
};
function renvoi(destination) {
  const r = RENVOIS[destination];
  if (!r) {
    return `<span class="capsum-link" style="color:var(--warn)">${esc(destination)} <span>${LANG === 'en' ? '(destination not named)' : '(destination non nommée)'}</span></span>`;
  }
  return `<a class="capsum-link" href="${esc(destination)}" title="${esc(r.titre)}">${esc(r.nom)} →</a>`;
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
    renvoi('#freshness-view') + renvoi('#sources') + `</div>`;
  const hosts = (d.hosts || []).length
    ? d.hosts.map(h => `<div class="kv"><span>${ic('server')} ${esc(h.host)}</span><span class="muted">${fmtTs(h.last_seen)}</span></div>`).join('')
    : '<div class="muted">hôte local uniquement — aucun agent distant n\'a encore poussé de logs.</div>';
  // P3.2-a — LE COMPTE D'HÔTES MUETS, seul chiffre de ce panneau qui parle des machines qui se sont tues
  // (les sondes ci-dessus ne le peuvent pas : leur portée les en empêche). `flotte` absent/null = la
  // lecture de l'inventaire a échoué -> on l'ÉCRIT au lieu d'afficher un zéro rassurant.
  // P11.10-a — LA PART DÉCLARÉE EST DITE. Un compte qui rétrécit sans dire pourquoi se lit comme une
  // amélioration ; « aucun muet » là où des machines muettes ont simplement été déclarées telles serait
  // faux. La phrase porte donc le compte hors-alerte quand il existe, et rien quand il n'existe pas.
  //
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // `P11.20-k` — LE NOMBRE D'HÔTES ET LA LISTE D'HÔTES NE COMPTENT PAS LA MÊME POPULATION, ET LA
  // DIFFÉRENCE SE LIT MAINTENANT SUR L'ÉCRAN.
  //
  // CE QUI A ÉTÉ MESURÉ DANS LE DÉMON, ET QUI NE SE DEVINAIT PAS D'ICI. Les deux lectures de cette
  // colonne partent de la MÊME table et de la MÊME requête (`host_rollup`, `WHERE host<>'' GROUP BY
  // host`) — et n'ont pourtant pas la même population. `host_inventory_simple`
  // (`daemon/src/handlers/fleet.rs`) rend TOUTES les machines, c'est la liste rendue ci-dessous.
  // `flotte_muette` (`daemon/src/sonde_de_flotte.rs`) parcourt les mêmes lignes mais SAUTE celles
  // qu'un exploitant a déclarées retirées du parc, AVANT d'incrémenter `attendus` — parce qu'un
  // dénominateur qui compte des machines dont quelqu'un a dit qu'elles n'en font plus partie ne veut
  // plus rien dire. Le total est donc toujours INFÉRIEUR OU ÉGAL au nombre de lignes listées, et
  // l'écart entre les deux est exactement le nombre de machines déclarées retirées.
  //
  // CE QUE LE PANNEAU EN DISAIT, ET LA DIRECTION DE L'ERREUR. Il écrivait « N hôte(s) inventoriés »
  // au-dessus de la liste : le mot promettait la liste, le nombre en comptait MOINS, et rien ne
  // rattachait l'un à l'autre. L'erreur allait donc dans le sens où le lecteur cherche une machine
  // qui manquerait — alors que rien ne manque, et que la seule chose absente était la phrase.
  //
  // LES TROIS NOMBRES DE LA FLOTTE SE PARTAGENT LEUR TOTAL PAR CONSTRUCTION : la sonde compte une
  // machine attendue, puis la range dans exactement l'une des trois issues — elle signale, elle est
  // muette, elle est muette au silence déclaré. C'est une répartition, et ce module a déjà la
  // fabrique qui rend une répartition lisible (`P11.16-b`) ; ce bloc était le seul de la surface à
  // poser ses nombres à côté d'elle, avec un « + » qui promettait une addition sans jamais dire à
  // quel total. `qui signalent` est DÉRIVÉ des trois autres, jamais servi : s'il devenait négatif, la
  // répartition aurait cessé d'en être une, et il est rendu tel quel plutôt que ramené à zéro — un
  // zéro fabriqué dirait que tout va bien là où la lecture ne se recompose plus.
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  const fl = d.flotte;
  const listees = (d.hosts || []).length;
  const rangeeDeFlotte = (f) => {
    const attendus = Number(f.attendus) || 0, muets = Number(f.muets) || 0, tus = Number(f.muets_declares_attendus) || 0;
    const minutes = Math.round((Number(f.seuil_s) || 0) / 60);
    return `<div class="capsum">` + rangeeDeChiffres([
      { famille: 'total', valeur: attendus, libelle: LANG === 'en' ? 'host(s) in the expected estate' : 'hôte(s) au parc attendu',
        titre: LANG === 'en' ? 'Machines seen at least once and NOT declared withdrawn from the estate. The total is shared by the three terms joined by « + ».' : 'Machines vues au moins une fois et NON déclarées retirées du parc. Le total se partage entre les trois termes reliés par « + ».' },
      { famille: 'part', valeur: attendus - muets - tus, libelle: LANG === 'en' ? 'signalling' : 'qui signalent',
        titre: LANG === 'en' ? 'A signal arrived recently enough for this machine not to be counted mute.' : 'Un signal est arrivé assez récemment pour que la machine ne soit pas comptée muette.' },
      { famille: 'part', valeur: muets, dot: 'muet', libelle: LANG === 'en' ? 'mute' : 'muet(s)',
        titre: (LANG === 'en' ? 'No signal at all for more than ' : 'Aucun signal depuis plus de ') + minutes + (LANG === 'en' ? ' min, and nobody declared that silence: to investigate.' : ' min, et personne n\'a déclaré ce silence : à investiguer.') },
      { famille: 'part', valeur: tus, libelle: LANG === 'en' ? 'at declared silence' : 'au silence déclaré',
        titre: LANG === 'en' ? 'Mute too, but someone declared that silence expected: counted apart, and out of the alert.' : 'Muettes elles aussi, mais quelqu\'un a déclaré ce silence attendu : comptées à part, et hors alerte.' },
    ]) + `</div>`;
  };
  // LE RATTACHEMENT DE LA LISTE À SON TOTAL — DÉRIVÉ des deux nombres, jamais supposé. L'écart n'est
  // pas tu quand il vaut zéro : un rattachement qui disparaît à zéro ne se distingue plus d'un
  // rattachement qui n'a jamais été écrit, et c'est exactement le défaut qu'on ferme ici.
  const rattachementDeLaListe = (f) => {
    const ecart = listees - (Number(f.attendus) || 0);
    const phrase = ecart === 0
      ? (LANG === 'en' ? `the ${listees} machine(s) listed below are exactly that total` : `les ${listees} machine(s) listée(s) ci-dessous sont exactement ce total`)
      : ecart > 0
        ? (LANG === 'en' ? `${listees} machine(s) listed below, ${ecart} more than that total: a machine DECLARED withdrawn from the estate stays listed and leaves the denominator` : `${listees} machine(s) listée(s) ci-dessous, ${ecart} de plus que ce total : une machine DÉCLARÉE retirée du parc reste listée et sort du dénominateur`)
        : (LANG === 'en' ? `${listees} machine(s) listed below, fewer than that total: the two readings do not agree — they are taken one after the other` : `${listees} machine(s) listée(s) ci-dessous, moins que ce total : les deux lectures ne s'accordent pas — elles sont prises l'une après l'autre`);
    return `<div class="muted flrattache" style="font-size:11px">${esc(phrase)}</div>`;
  };
  const flotteLigne = fl === undefined ? ''
    : fl === null ? '<div class="kv"><span class="muted">hôtes muets : inventaire illisible (aucun verdict rendu)</span></div>'
    : rangeeDeFlotte(fl) + rattachementDeLaListe(fl);
  // caption : sépare EXPLICITEMENT les 2 axes (couverture de sondes vs endpoints) et renvoie la SANTÉ à Fraîcheur.
  const cap = `<div class="muted intplug" style="font-size:11px">Capteurs = <b>couverture</b> (types de sondes déclarés ; un capteur mort est signalé <b>muet</b> ici) · Hôtes = <b>endpoints</b> (où les agents poussent). La santé fine par source (frais/calme/en retard/muet) vit dans Fraîcheur — « en retard » y désigne la même observation que « muet » ici, au même seuil.</div>`;
  // lien de découverte -> la Flotte (inventaire détaillé des hôtes : statut/enrôlement/dernier signal, paginé + export).
  const hostsHdr = `Hôtes (endpoints) ${renvoi('#fleet')}`;
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
// `P11.18-f` — LA PASTILLE, LA COULEUR ET LE RANG NE SONT PLUS ÉCRITS ICI.
//
// CE QUI A ÉTÉ MESURÉ. L'inventaire des sources et cette vue rendaient le même statut, dérivé côté démon
// par la MÊME fonction (`statut_de_source`), à partir de la même mesure ; côté console, chacune tenait sa
// PROPRE table de pastilles et de couleurs. Les deux tables s'accordaient — et c'est exactement l'état
// d'un miroir la veille du jour où il diverge : rien ne signalerait qu'un mot a changé de ton d'un seul
// côté. La table vit désormais dans `sources.js`, où elle est déjà canonique, et cette surface la LIT.
//
// CE QUE CETTE SURFACE GARDE EN PROPRE : les cinq états qu'elle peut RECEVOIR (le vocabulaire canonique
// en porte un sixième, `dormant`, qu'un flux ne peut pas prendre — une source dormante n'a aucun flux),
// et les libellés LONGS qui définissent chaque état pour un lecteur de cette vue.
const FSTATES = ['muet', 'en_retard', 'attente', 'frais', 'calme'];
function freshState(f) {
  const e = etatDeSource(f.status);
  return FSTATES.includes(e) ? e : 'calme';
}
const pastilleDEtat = (etat) => (ETAT_DE_SOURCE[etat] ? ETAT_DE_SOURCE[etat].dot : 'calme');
const couleurDEtat = (etat) => (ETAT_DE_SOURCE[etat] ? ETAT_DE_SOURCE[etat].txt : 'bad');
// libellé d'en-tête de groupe quand on regroupe PAR ÉTAT
const FSTATE_LBL = { muet: 'muet — plus rien n\'arrive, toutes sources confondues', en_retard: 'en retard — cadence déclarée dépassée', attente: 'en attente — déclaré, pas encore de donnée', frais: 'frais (donnée < 15 min)', calme: 'calme (collecte saine, source peu active)' };
// LE RANG DE TRI vient de la même table canonique : panne en haut ; puis en retard, en attente, frais, calme.
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
// compteurs par état + alertes actives — même agrégation pour le détail et le pulse. LES CINQ ÉTATS SE
// PARTAGENT `feeds.length` PAR CONSTRUCTION : `freshState` a un repli, donc chaque flux incrémente
// exactement un état, et c'est là toute la rangée de tête. `alertes` compte sur la MÊME population sans
// la partager : il ne paraît plus dans cette rangée, mais dans la zone qui porte les nombres d'alertes
// (`P11.18-d`) — sa place le dit, aucune phrase n'a plus à le dire.
function countStates(feeds) {
  const scount = { muet: 0, en_retard: 0, attente: 0, frais: 0, calme: 0, alertes: 0 };
  feeds.forEach(f => { scount[freshState(f)] += 1; if (Number(f.active_alerts) > 0) scount.alertes += 1; });
  return scount;
}
// LE LIBELLÉ COURT D'UN ÉTAT vient du vocabulaire canonique (`sources.js`) : c'est le MOT MÊME que la
// colonne « Statut » de l'inventaire pose sur ses lignes, écrit une seule fois pour les deux surfaces
// (`P11.18-f`). À défaut d'entrée canonique — un état que le démon rendrait avant que la table ne le
// connaisse — il reste DÉRIVÉ du libellé long de ce module : le long porte la définition (« — … » ou
// « (…) »), le court en est le premier segment ; sans séparateur, c'est le libellé entier qui est rendu
// — trop long dans la rangée, donc VISIBLE, jamais silencieux.
const libelleCourtDEtat = (etat) => (ETAT_DE_SOURCE[etat] && ETAT_DE_SOURCE[etat].court)
  || String(FSTATE_LBL[etat] || etat).split(/ [—(]/)[0].trim();
// L'ORDRE DE LECTURE des parts : du plus sain au plus grave, l'inverse exact du rang de tri du détail
// (`SRANK`, la panne en haut). Une seule table de rang, lue dans les deux sens — pas une seconde liste.
const ETATS_DE_LA_RANGEE = [...FSTATES].sort((a, b) => rangDEtatDeSource(b) - rangDEtatDeSource(a));
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// `P11.18-d` — QUAND UNE PHRASE NE SUFFIT PAS, C'EST LA PLACE QUI PARLE.
//
// LA SECONDE FOIS. `P11.16-b` avait séparé ce qui PARTAGE un total de ce qui le RECOUPE, et écrit la
// distinction sur l'écran : le compte des flux porteurs d'alertes actives était introduit par « dont »,
// avec l'aveu au survol qu'une alerte n'est pas un état de collecte. Relevé en usage réel : ce n'est
// TOUJOURS pas clair. Une source de bordure porte deux vraies alertes — un balayage absorbé au bord,
// une reconnaissance lente — qui ne disent rien de sa fraîcheur, et le nombre continue d'être lu comme
// un état de collecte. La vue le démentait pourtant en toutes lettres, deux fois.
//
// CE QUI A ÉCHOUÉ, ET POURQUOI UNE TROISIÈME PHRASE ÉCHOUERAIT AUSSI. Le nombre était posé DANS la
// rangée qui répartit les états de collecte, sous le même jeton, séparé des autres par un seul mot. Une
// rangée se lit d'un coup d'œil ; le mot qui la coupe se lit après, s'il se lit. Tant que ce compte est
// rendu parmi les états, il sera lu comme un état — quel que soit le texte à côté.
//
// CE QUE L'EXPLOITANT VIENT CHERCHER ICI, ÉTABLI ET NON SUPPOSÉ. La section d'aide de cette vue
// (`web/help_registry.js`, clé `freshness`) l'écrit en première ligne : « ÉTAT = SANTÉ DE COLLECTE (pas
// l'activité) ». C'est la vue qu'on ouvre pour savoir si la donnée ARRIVE ENCORE, donc pour décider si
// l'on peut faire confiance à ce que les autres vues montrent. Un compte d'alertes ne répond pas à
// cette question-là : il répond à « qu'a-t-on détecté ? », qui est la question d'une autre vue.
//
// LA DÉCISION. Le compte QUITTE la grammaire de la collecte : il n'est plus un terme de cette rangée,
// qui redevient une répartition pure — total, cinq parts, rien d'autre. Il est REGROUPÉ, avec les
// autres nombres d'alertes de cette vue, dans une zone à lui, en bas, sous une séparation qui n'est pas
// une phrase : un filet, un nom, et le renvoi vers la vue à laquelle ces nombres appartiennent.
//
// POURQUOI IL RESTE DANS LA VUE PLUTÔT QUE D'EN PARTIR. Ces nombres se rapportent aux FLUX listés ici,
// et à eux seuls : ce sont les alertes imputées à ces flux, et la répartition qui les accompagne est le
// seul endroit de la console où l'on vérifie qu'aucune alerte active ne se perd entre celles qu'une
// cloche porte, celles qui ne se rapportent à aucun flux et celles dont l'imputation n'a jamais été
// enregistrée. Les emporter ailleurs les couperait de la liste qu'ils qualifient. CE QUI CHANGE, ALORS,
// c'est la place — et les deux phrases qui avaient échoué sont RETIRÉES : rien ne remplace un filet.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// LA RANGÉE DE FRAÎCHEUR : un total et cinq parts qui se le partagent, plus aucun recoupement. La
// fabrique de familles reste celle de `P11.16-b` — elle sert encore la rangée d'Intégrations, dont le
// recoupement (« à portée tous hôtes confondus ») EST, lui, une propriété des capteurs comptés.
function summaryPills(feeds) {
  const sc = countStates(feeds);
  return rangeeDeChiffres([
    { famille: 'total', valeur: feeds.length, libelle: LANG === 'en' ? 'feed(s) observed' : 'feed(s) observé(s)',
      titre: LANG === 'en' ? 'The row recomposes: the total is the sum of the terms joined by « + », and this row holds nothing else.' : 'La rangée se recompose : le total est la somme des termes reliés par « + », et cette rangée ne porte rien d\'autre.' },
    ...ETATS_DE_LA_RANGEE.map(e => ({ famille: 'part', valeur: sc[e], dot: pastilleDEtat(e), libelle: libelleCourtDEtat(e), titre: FSTATE_LBL[e] })),
  ]);
}

// LA ZONE DES ALERTES — tous les nombres d'alertes de cette vue, et eux seuls. Le filet et le nom sont
// la séparation ; le renvoi dit où ces nombres vivent. `bloc` est la répartition servie par le démon,
// rendue seulement quand elle a quelque chose à répartir.
function zoneDesAlertes(sc, bloc) {
  const compte = rangeeDeChiffres([
    { famille: 'recoupement', valeur: sc.alertes, cloche: true,
      libelle: LANG === 'en' ? 'with active alerts' : 'avec alertes actives',
      titre: LANG === 'en' ? 'Number of feeds listed above to which at least one unacknowledged alert is attributed, all dates, cases included. Each of them carries a bell on its line, which opens exactly those alerts.' : 'Nombre de flux listés ci-dessus auxquels au moins une alerte non acquittée est imputée, toutes dates, cases comprises. Chacun porte une cloche sur sa ligne, qui ouvre exactement ces alertes.' },
  ]);
  return `<div class="fimput" style="margin-top:14px;border-top:1px solid var(--bd);padding-top:9px">` +
    `<div class="fldname">${LANG === 'en' ? 'Alerts attributed to these feeds' : 'Alertes imputées à ces flux'}</div>` +
    `<div class="capsum">${compte}${renvoi('#alerts')}</div>${bloc}</div>`;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// `P11.18-g` — L'ORDRE INTERNE D'UN GROUPE SE CHOISIT, ET LE CHOIX SE RETIENT.
//
// LE CONSTAT. Les flux sont groupés par état — c'est le bon axe, et il ne change pas. Mais DANS un
// groupe, l'ordre suivait l'ancienneté de la dernière donnée : il sert à repérer ce qui vient de
// bouger, pas à RETROUVER une source qu'on cherche par son nom dans une liste qui grandit.
//
// LE TRI VIENT DU MÉCANISME PARTAGÉ, PAS D'UNE COMPARAISON ÉCRITE ICI. `colComparator` (core.js) est
// celui du tri par colonne des listes partagées : il MESURE le type des valeurs de la colonne (adresse,
// nombre, texte) au lieu de le supposer, puis rend le comparateur qui va avec. Une liste de noms
// numériques se classera donc numériquement sans qu'une ligne soit écrite pour ce cas.
//
// LE CHOIX EST MÉMORISÉ COMME L'EST LE PLIAGE — par le magasin de préférences PARTAGÉ (`prefs.js`),
// qui survit au re-rendu de l'auto-rafraîchissement, au rechargement de la page et au changement de
// poste (il est adossé au démon), là où le pliage ne tient que dans le stockage local du navigateur.
// CE QUI N'EXISTE PAS ENCORE et qui manque : un CONTRÔLE d'ordre dans la fabrique de listes elle-même.
// `pagedList` n'offre le choix qu'aux TABLEAUX (clic d'en-tête, non mémorisé) ; deux panneaux de
// l'administration de la détection tiennent chacun leur sélecteur et leur clé. Cette vue est la
// troisième écriture de la même idée : sa place est dans `core.js`, à côté de « Grouper par ».
const ORDRES_DANS_UN_ETAT = [
  { cle: 'anciennete', lire: f => f.age_s, sens: -1,
    nom: LANG === 'en' ? 'oldest data first' : 'donnée la plus ancienne d\'abord' },
  { cle: 'nom', lire: f => f.name, sens: 1,
    nom: LANG === 'en' ? 'by name (A → Z)' : 'par nom (A → Z)' },
];
const CLE_D_ORDRE = 'freshness.ordre-dans-un-etat';
// Un choix mémorisé que la table ne connaît plus (ordre retiré, préférence d'une version antérieure)
// retombe sur le premier — l'ordre historique — jamais sur un tri vide.
const ordreDansUnEtat = () => ORDRES_DANS_UN_ETAT.find(o => o.cle === prefGet(CLE_D_ORDRE, '')) || ORDRES_DANS_UN_ETAT[0];
function trierDansUnEtat(arr, ordre) {
  const cmp = colComparator(arr, ordre.lire);
  arr.sort((a, c) => (cmp(a, c) * ordre.sens) || String(a.name).localeCompare(String(c.name)));
  return arr;
}
function barreDOrdre(ordre) {
  const opts = ORDRES_DANS_UN_ETAT.map(o => `<option value="${esc(o.cle)}"${o.cle === ordre.cle ? ' selected' : ''}>${esc(o.nom)}</option>`).join('');
  const titre = LANG === 'en' ? 'Order of the feeds INSIDE each state. The choice is remembered, as the folding of the groups is.' : 'Ordre des flux À L\'INTÉRIEUR de chaque état. Le choix est mémorisé, comme l\'est le pliage des groupes.';
  const mot = LANG === 'en' ? 'order inside each state — the grouping by state does not change' : 'ordre à l\'intérieur de chaque état — le regroupement par état ne change pas';
  return `<div class="flegend"><select class="picon" data-ordre title="${esc(titre)}">${opts}</select>` +
    `<span class="muted">${esc(mot)}</span></div>`;
}

// RENDU PUR du détail à partir de la charge utile de /api/freshness (exercé par le harnais ESM sur des objets
// fabriqués). Renvoie le HTML ; `renderFreshness` le pose et câble les gestes.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// `P11.21-i` — CE PANNEAU AVAIT LE DÉFAUT DANS L'AUTRE SENS, ET C'EST LE PLUS DANGEREUX DES DEUX.
//
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ DE LA CLÉ, MESURÉ LE 2026-08-30 : il annonçait que ces vues
// « prennent la branche du refus dès qu'une cause apparaît, donc jettent les données reçues ». Les deux
// vues de la fraîcheur ne prenaient AUCUNE branche : `error` n'était lu NULLE PART dans ce module. Elles
// ne rendaient donc pas MOINS que ce qui est su, elles rendaient PLUS — un relevé TRONQUÉ servi comme
// un relevé COMPLET, sans un mot. C'est le sens optimiste de l'erreur, celui dont un exploitant ne peut
// même pas soupçonner qu'il manque quelque chose, et il n'est pas rattrapé par la prudence.
//
// LA ROUTE EST AUSSI LA PLUS EXPOSÉE DES TROIS, ET CE N'EST PAS UNE INTUITION. (a) Son corps est
// alimenté par PLUSIEURS parcours indépendants (`ParcoursDeFraicheur`, `daemon/src/handlers/freshness.rs`)
// et la cause paraît dès qu'UN SEUL n'est pas allé au bout — c'est une union, pas un parcours unique.
// (b) L'un d'eux lit `alert WHERE status='new'` EN ENTIER, sans borne de fenêtre, là où les deux routes
// de couverture lisent des agrégats bornés et indexés : c'est exactement le parcours que la garde de
// budget coupe. (c) Elle est la seule des trois à être une charge VIVE du registre
// (`navigation.js`) : le pulse repart à chaque tir de cadence sur la vue d'ensemble — la vue d'arrivée —
// et se re-poll toutes les 3 s pendant le préchauffage, quand les deux panneaux de couverture sont des
// CATALOGUES qui ne partent qu'à l'entrée dans leur onglet ou sur un geste de rafraîchissement.
//
// LES TROIS ÉTATS SONT DÉRIVÉS DU CORPS, JAMAIS DE LA ROUTE, ET LA LECTURE EST À UN CRAN : la jambe B de
// `check_a_refusal_is_not_rendered_as_an_absence.py` dérive ses lecteurs des fonctions du MÊME module
// dont le corps PROPRE porte `.error`. Cette fonction en est une ; interposer une indirection de plus
// l'aveuglerait, et la factorisation vers le point commun est interdite par la même forme.
function etatDuReleveServi(d) {
  const cause = (d && d.error != null) ? String(d.error).trim() : '';
  const flux = (d && d.feeds) || null;
  const servis = (flux && flux.length) ? flux.length : 0;
  return { cause, servis, refus: !!cause && servis === 0, incomplet: !!cause && servis > 0 };
}
// La phrase du RELEVÉ NON LU. Bilingue par construction ; la cause du démon est collée telle quelle —
// elle est écrite une seule fois côté démon, la redire ici en ferait un porteur qui vieillirait.
function motDuReleveNonLu(cause) {
  return LANG === 'en'
    ? 'Source freshness NOT READ: the daemon declined and names the cause — "' + cause
      + '" This is NOT an absence: no feed was read, so nothing here establishes that no source is reporting.'
    : "Fraîcheur des sources NON LUE : le démon a refusé et en nomme la cause — « " + cause
      + " » Ce n'est PAS une absence : aucun flux n'a été lu, donc rien ici n'établit qu'aucune source ne remonte.";
}
// La phrase du RELEVÉ PARTIEL. Elle n'est PAS celle du refus : « aucun flux n'a été lu » serait faux ici.
// Elle n'ajoute que ce que le démon ne peut pas savoir — quelle vue a été demandée, et que ce qui suit
// est ce préfixe.
function motDuRelevePartiel(cause) {
  return LANG === 'en'
    ? 'Source freshness PARTIALLY READ — the daemon served feeds AND names a cause: "' + cause
      + '" What is displayed below is that partial read, and nothing more.'
    : "Fraîcheur des sources PARTIELLEMENT LUE — le démon a servi des flux ET en nomme la cause : « " + cause
      + " » Ce qui est affiché ci-dessous est cette lecture partielle, et rien de plus.";
}
// Le bandeau, dans le registre de l'aveu. Vide — donc byte-neutre — sur une lecture entière.
function bandeauDeReleveIncomplet(etat) {
  return etat.incomplet ? '<div class="bad">' + esc(motDuRelevePartiel(etat.cause)) + '</div>' : '';
}

function renderFreshnessDetail(d) {
  const feeds = (d.feeds || []).slice();
  // P11.16-a — COMBIEN de flux de cette liste ne sont PAS des sources d'événements : l'inventaire, qui
  // nomme les producteurs, ne porte que celles-là (voir la légende, plus bas). Dérivé des flux rendus.
  const horsEvenement = feeds.filter(f => f && f.kind !== 'event').length;
  feeds.sort((a, c) => (rangDEtatDeSource(freshState(a)) - rangDEtatDeSource(freshState(c))) || a.name.localeCompare(c.name));
  // le STATUT = santé de collecte : muet seulement si l'ingestion est en panne ; en retard seulement au-delà
  // d'une cadence DÉCLARÉE ; sinon l'âge est INFORMATIF.
  // `P11.21-i` — L'AVEU DE RACINE PRÉCÈDE TOUT LE RESTE, y compris la ligne d'état de la collecte : un
  // démenti posé plus bas serait rencontré APRÈS les groupes par un lecteur qui va de haut en bas.
  // MESURE QUI ÉVITE UNE FAUSSE ACCUSATION : `pipeline_fresh` ne vient PAS du parcours des flux — il est
  // lu par un `query_row` séparé sur `MAX(ts)` (`daemon/src/handlers/freshness.rs`). Une coupe des flux
  // ne peut donc pas FABRIQUER la bannière « Ingestion en panne », et rien ici n'a à la neutraliser.
  const aveuDeRacine = bandeauDeReleveIncomplet(etatDuReleveServi(d));
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
  // `P11.21-i` — LE PARTAGE PORTE SA PROPRE CAUSE, ET ELLE EST LUE ICI MÊME. Le démon la pose DANS
  // `imputation_des_alertes` (`CAUSE_IMPUTATION_NON_ETABLIE`) précisément pour qu'un consommateur qui ne
  // lit que ce sous-objet ne soit pas trompé — ce module ne lisait ni celle-ci ni celle de la racine, et
  // rendait quatre nombres qui se retrouvent entre eux comme s'ils portaient sur TOUTES les alertes
  // actives. Un compte tronqué ne raccourcit rien : il rend une somme qui a l'air juste.
  const causeDuPartage = (imp && imp.error != null) ? String(imp.error).trim() : '';
  let bloc = '';
  if (causeDuPartage && actives === 0) {
    // Rien n'a été compté ET une cause est servie : ne rien afficher se lirait « aucune alerte active ».
    bloc = '<div class="bad">' + esc(LANG === 'en'
      ? 'Active-alert split NOT ESTABLISHED: the daemon declined and names the cause — "' + causeDuPartage
        + '" This is NOT an absence: nothing was counted, so nothing here establishes that no alert is active.'
      : "Partage des alertes actives NON ÉTABLI : le démon a refusé et en nomme la cause — « " + causeDuPartage
        + " » Ce n'est PAS une absence : rien n'a été compté, donc rien ici n'établit qu'aucune alerte n'est active.") + '</div>';
  }
  if (imp && actives > 0) {
    const jeton = String(imp.jeton_sans_source || '');
    const parts = [`${ic('bell')} <b>${actives}</b> alerte(s) active(s) : <b>${Number(imp.avec_cloche) || 0}</b> imputée(s) à un flux (leur cloche est allumée ci-dessous)`];
    if (orph > 0) {
      parts.push(`<b>${orph}</b> <span class="forph" role="button" tabindex="0" data-src="${esc(jeton)}" title="Ces alertes DISENT qu'elles ne se rapportent à aucun flux : une alerte d'hôte, de règle ou de seuil n'en a pas. Ce n'est pas un défaut de collecte. Cliquer pour les voir.">sans flux (normal pour une alerte d'hôte, de règle ou de seuil)</span>`);
    }
    if (muettes > 0) {
      parts.push(`<b>${muettes}</b> <span title="Aucune imputation enregistrée et rien de nommable dans leur texte : alertes levées avant l'imputation, ou par un producteur qui ne l'écrit pas. Le compte par source les ignore — c'est dit ici plutôt que tu.">sans imputation enregistrée (le compte par source les ignore)</span>`);
    }
    // L'aveu PRÉCÈDE les nombres, pour la même raison qu'ailleurs. Vide sur un parcours complet.
    const aveuDuPartage = causeDuPartage
      ? '<div class="bad">' + esc(LANG === 'en'
        ? 'Active-alert split PARTIALLY READ — the daemon served the counts AND names a cause: "' + causeDuPartage
          + '" The numbers below are that partial read, and nothing more.'
        : "Partage des alertes actives PARTIELLEMENT LU — le démon a servi les comptes ET en nomme la cause : « " + causeDuPartage
          + " » Les nombres ci-dessous sont cette lecture partielle, et rien de plus.") + '</div>'
      : '';
    bloc = aveuDuPartage + `<div class="muted" style="margin-top:6px">${parts.join(' · ')}.</div>`;
  }
  // une SÉRIE métrique (sous le feed agrégé déplié) : même modèle d'état que les sources (statut du démon).
  const seriesRow = s => {
    const ss = freshState(s);
    return `<div class="kv fseries"><span><span class="fdot ${pastilleDEtat(ss)}"></span>${esc(s.name)}</span>` +
      `<b class="${couleurDEtat(ss)}" title="dernière donnée ${fmtTs(s.last_seen)}">il y a ${age(s.age_s)}</b></div>`;
  };
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // `P11.18-n` — UNE LIGNE PORTEUSE D'ALERTES N'EST PLUS REPEINTE, ET LA MARQUE N'EST PLUS UNE
  // PROPRIÉTÉ DE LA LIGNE.
  //
  // LE CONSTAT, ET CE QUI L'ÉCLAIRE. Une source portant des alertes actives recevait une classe qui
  // teintait TOUTE sa ligne — et la teinte employée était celle de l'avertissement, c'est-à-dire
  // dans cette vue précise la couleur de l'état « en retard » (l'âge d'une ligne en retard est rendu
  // avec la même valeur). Le signal de PLACE et le signal de COULEUR disaient donc tous deux
  // « problème de collecte » à propos d'un compte d'alertes. `P11.18-d` a sorti le compte de la
  // grammaire de la collecte ; c'est ce marquage-ci qui expliquait le reste de la confusion.
  //
  // LA COULEUR NE POUVAIT PAS ÊTRE REMPLACÉE PAR UNE AUTRE. Les cinq états de cette vue RÉSERVENT
  // chacun la leur, pastille et encre — frais, calme, en retard, en attente, muet. Relevé dans les
  // deux thèmes le 2026-08-25 : il n'en reste aucune de libre, l'accent VALANT le vert « frais »
  // sous le thème clair. Et le défaut ne tenait pas qu'à la teinte : ce qui vaut pour la LIGNE
  // ENTIÈRE appartient ici à la grammaire de l'état — la pastille l'ouvre, l'âge coloré la ferme —
  // donc une ligne repeinte se lit comme un état, quelle que soit la couleur.
  //
  // LA MARQUE EST DONC UN OBJET DANS LA LIGNE, PAS LA LIGNE. C'est la cloche : un GLYPHE que rien
  // d'autre ne pose sur une ligne, le NOMBRE d'alertes et un CADRE — trois canaux qui survivent en
  // monochrome, comme le chevron du dépli partagé. Elle reste le seul élément de la ligne
  // atteignable au clavier, son intitulé nomme le compte, et elle ouvre exactement ces alertes.
  // CE QU'ELLE NE FAIT PAS, ÉCRIT PLUTÔT QUE TU : elle ne forme pas une colonne — sa position suit
  // la longueur du nom et de la cadence — donc elle se repère par sa forme, non par un balayage
  // vertical. Le COMBIEN se lit d'un coup dans la zone des alertes, qui le porte pour la vue.
  //
  // LA RÈGLE DE STYLE ET LA CLASSE SONT PARTIES ENSEMBLE : une classe sans règle ne peint rien, et
  // une règle sans cible est refusée par la garde des sélecteurs, dont le plafond est zéro.
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  const rowOf = f => {
    const st = freshState(f);
    if (f.kind === 'metric') {
      const sList = f.series || [];
      const open = S.freshCollapsed.has('metric-open');
      const body = sList.length
        ? `<div class="fmetricbody">${sList.map(seriesRow).join('')}</div>`
        : `<div class="fmetricbody muted" style="padding:4px 0 0 18px">détail des séries indisponible (mettre à jour le daemon)</div>`;
      const hd = `<div class="kv fmetrichd" role="button" tabindex="0" aria-expanded="${open ? 'true' : 'false'}" title="Plier / déplier les séries métriques">` +
        `<span><span class="fchev">${ic('chevright')}</span><span class="fdot ${pastilleDEtat(st)}"></span>${esc(f.name)} <span class="muted fkind" title="${esc(cadenceTitle(f))}">${esc(cadenceLabel(f))}</span></span>` +
        `<b class="${couleurDEtat(st)}">il y a ${age(f.age_s)}</b></div>`;
      return `<div class="fmetric${open ? '' : ' collapsed'}">${hd}${body}</div>`;
    }
    const porteDesAlertes = Number(f.active_alerts) > 0;
    const badge = porteDesAlertes ? ` <span class="fhot" role="button" tabindex="0" data-src="${esc(f.name)}" title="${f.active_alerts} alerte(s) non acquittée(s) imputée(s) à ${esc(f.name)}, toutes dates (cases comprises) · cliquer pour les ouvrir dans Alertes">${ic('bell')} ${f.active_alerts}</span>` : '';
    // « en retard » : la raison est DITE sur la ligne (cadence déclarée, sonde, silence), pas seulement coloriée.
    const reason = st === 'en_retard'
      ? `en retard — aucune donnée depuis ${age(f.age_s)} pour une cadence déclarée de ${age(f.cadence_interval_s || 0)} (sonde « ${f.cadence_capteur || '?'} »)`
      : '';
    const why = reason ? ` <span class="muted fwhy">· au-delà de ${age(f.cadence_interval_s || 0)}</span>` : '';
    return `<div class="kv"${reason ? ` title="${esc(reason)}"` : ''}><span><span class="fdot ${pastilleDEtat(st)}"></span>${esc(f.name)} <span class="muted fkind" title="${esc(cadenceTitle(f))}">${esc(cadenceLabel(f))}</span>${badge}${why}</span>` +
      `<b class="${couleurDEtat(st)}" title="dernière donnée ${fmtTs(f.last_seen)}">il y a ${age(f.age_s)}</b></div>`;
  };
  // GROUPES PAR ÉTAT : chaque état est une section repliable (libellé + nombre + pastille), tri DANS le groupe
  // le plus PÉRIMÉ d'abord (age décroissant). Par défaut seul « calme » est replié (voir init de
  // freshCollapsed). État persisté dans freshCollapsed (clé 'cat:<état>' présente = REPLIÉ).
  const groups = new Map();
  feeds.forEach(f => { const c = freshState(f); if (!groups.has(c)) groups.set(c, []); groups.get(c).push(f); });
  const cats = [...groups.entries()].sort((a, c) => rangDEtatDeSource(a[0]) - rangDEtatDeSource(c[0]));
  const summaryLine = `<div class="capsum">${summaryPills(feeds)}${renvoi('#sources')}</div>`;
  const ordre = ordreDansUnEtat();
  let html = aveuDeRacine + head0 + summaryLine + barreDOrdre(ordre);
  for (const [cat, arr] of cats) {
    trierDansUnEtat(arr, ordre);
    const collapsed = S.freshCollapsed.has('cat:' + cat);
    const lbl = FSTATE_LBL[cat] || cat;
    html += `<div class="fgroup${collapsed ? ' collapsed' : ''}" data-cat="${esc(cat)}">` +
      `<button type="button" class="fgrouphd" aria-expanded="${collapsed ? 'false' : 'true'}" title="Plier / déplier ${esc(lbl)}">` +
      `${ic('chevdown')}<span class="fdot ${pastilleDEtat(cat)}"></span><span class="fglbl">${esc(lbl)}</span><span class="fgcount">${arr.length}</span></button>` +
      // `P11.21-b` — LE PANNEAU PORTE UN NOM, ET CE NOM EST DÉRIVÉ, JAMAIS INVENTÉ. `disclosure` ne pose
      // `aria-controls` que depuis l'identifiant du panneau ; sans lui, le bouton ne NOMME pas la région
      // qu'il commande. L'identifiant vient de `cat`, qui est déjà la clé de persistance du pli
      // (`cat:<état>`) et qui appartient au vocabulaire FERMÉ de `FSTATES` — cinq mots, tous
      // utilisables tels quels, et un groupe par état au plus dans la vue : l'unicité dans le document
      // est une propriété de la vue, pas un pari.
      `<div class="fgbody" id="fgbody-${esc(cat)}">${arr.map(rowOf).join('')}</div></div>`;
  }
  html += zoneDesAlertes(countStates(feeds), bloc);
  html += `<div class="flegend"><span class="fdot frais"></span>frais (donnée &lt; 15 min) · <span class="fdot calme"></span>calme (collecte saine, source peu active) · <span class="fdot warn"></span>en retard (cadence déclarée dépassée) · <span class="fdot attente"></span>en attente (déclaré, pas de donnée) · <span class="fdot muet"></span>muet (plus rien n'arrive, toutes sources confondues)` +
    `<div class="muted" style="margin-top:4px">${LANG === 'en' ? 'The expected cadence is the one a daemon probe or the operator DECLARES (shown next to the name, with its declarer on hover). An event-driven source, or one whose cadence nobody declared, is never “late”: its age only tells its activity, and that blank is not a fault — it is filled from the Source inventory (Data → Sources).' : 'La cadence attendue est celle qu\'une sonde du démon ou l\'exploitant DÉCLARE (affichée à côté du nom, avec son déclarant au survol). Une source événementielle, ou dont personne n\'a déclaré la cadence, n\'est jamais « en retard » : son âge ne dit que son activité, et ce blanc n\'est pas un défaut — il se comble depuis l\'Inventaire des sources (Données → Sources).'}</div>` +
    // P11.16-a — CE PANNEAU NE PEUT PAS NOMMER LE PRODUCTEUR : la charge utile de `/api/freshness` ne
    // porte que le NOM de la source (le rapprochement dérivé vit dans `/api/sources`). Plutôt que de
    // laisser croire qu'un nom de flux nomme le fichier qui l'émet, la légende dit où ce nom se trouve.
    // Phrase posée dans son PROPRE nœud : ajoutée au texte ci-dessus, elle l'aurait rendu intraduisible.
    //
    // ET LE RENVOI NE PROMET PLUS CE QUE L'INVENTAIRE NE PORTE PAS. Mesuré le 2026-08-26 :
    // `daemon/src/handlers/sources.rs` construit l'inventaire à partir d'`event_rollup` et des marquages —
    // il ne liste QUE des sources d'événements. Cette liste-ci porte en plus des flux d'un autre genre
    // (instantanés par `kind`, métriques agrégées) : leur envoyer un lecteur chercher « le producteur »
    // était un renvoi vers une ligne qui n'existe pas. Le COMPTE est DÉRIVÉ des flux rendus, jamais d'une
    // table de genres écrite ici : un genre neuf y entre sans qu'on l'écrive, et disparaît de la phrase
    // dès qu'aucun flux ne le porte.
    `<div class="muted" style="margin-top:4px">${horsEvenement
      ? (LANG === 'en' ? `A feed's name is the name of the SOURCE, not of the file that emits it — the two often differ. The inventory (Data → Sources) names the producer of EVENT sources, and of those only: the ${horsEvenement} feed(s) of this list that are not event sources do not appear there at all, so no producer can be read for them.` : `Le nom d'un flux est celui de la SOURCE, pas du fichier qui l'émet — les deux diffèrent souvent. L'inventaire (Données → Sources) nomme le producteur des sources d'ÉVÉNEMENTS, et d'elles seules : les ${horsEvenement} flux de cette liste qui n'en sont pas n'y figurent pas du tout, et aucun producteur ne s'y lit pour eux.`)
      : (LANG === 'en' ? 'A feed\'s name is the name of the SOURCE, not of the file that emits it — the two often differ. The inventory (Data → Sources) names the producer of EVENT sources, and every feed of this list is one.' : 'Le nom d\'un flux est celui de la SOURCE, pas du fichier qui l\'émet — les deux diffèrent souvent. L\'inventaire (Données → Sources) nomme le producteur des sources d\'ÉVÉNEMENTS, et tous les flux de cette liste en sont.')}</div></div>`;
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
  // `P11.21-i` — L'ÉTAT DE LA LECTURE SERVIE, LU À UN CRAN DE L'APPEL, SUR LE CORPS.
  const etat = etatDuReleveServi(d);
  // FROID : le serveur calcule la fraîcheur en async (~5s, scan 7j chiffré) et renvoie warming SANS bloquer.
  // On affiche un placeholder « … » (PAS un vide-définitif) et on re-poll de façon rapprochée jusqu'à ce que
  // la vraie valeur arrive — au lieu d'attendre le prochain tick d'auto-refresh (30s).
  if (d.warming) {
    clearTimeout(S.freshnessRepollTimer);
    S.freshnessRepollTimer = setTimeout(renderFreshness, 3000);
    // `P11.21-i` — LE PRÉCHAUFFAGE NE MANGE PLUS UNE CAUSE SERVIE. « mesure en cours » décrit l'état du
    // CALCUL, pas une absence : il reste rendu tel quel, mais il ne l'emporte plus sur un aveu du démon.
    // Le re-poll est armé AVANT, donc rien n'est perdu — le tir suivant repeindra dans 3 s.
    if (!etat.cause && !feeds.length) { b.innerHTML = '<div class="muted">… mesure de la fraîcheur des sources en cours</div>'; return; }
    // (cas rare) warming avec dernières valeurs connues -> on retombe sur l'affichage normal ci-dessous.
  } else {
    clearTimeout(S.freshnessRepollTimer); S.freshnessRepollTimer = null;
  }
  // LE REFUS AVANT LE VIDE, ET LES DEUX TESTS SÉPARÉS : « aucun feed récent » sur un corps qui NOMME sa
  // cause est une lecture non faite servie comme un fait — le vide le plus rassurant qui soit sur une
  // surface de collecte, servi précisément quand rien n'a été lu.
  if (etat.refus) { b.innerHTML = '<div class="bad">' + esc(motDuReleveNonLu(etat.cause)) + '</div>'; return; }
  if (!feeds.length) { b.innerHTML = '<div class="muted">aucun feed récent</div>'; return; }
  const html = renderFreshnessDetail(d);
  b.innerHTML = html;
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // `P11.21-b` — LES DEUX PLIAGES DE CE PANNEAU PASSENT PAR LE DÉPLI PARTAGÉ (`disclosure`, core.js).
  //
  // CE QUE LE CONSTAT DISAIT, ET CE QUE LA MESURE DU 2026-08-30 EN CORRIGE. Il annonçait HUIT sites de
  // dépli écrits à la main, quatre ici. Le compte de huit est EXACT si l'on compte les ÉCRITURES
  // d'`aria-expanded` hors commentaire (c'est ce que le témoin 53 du harnais compte) ; il ne l'est pas
  // si l'on compte des MÉCANISMES : ce module en portait DEUX (les groupes par état, les séries
  // métriques) et `alerts.js` UN — trois en tout, pas huit.
  //
  // CE QUI EST GAGNÉ, MESURÉ PLUTÔT QUE SUPPOSÉ, et `aria-expanded` n'en fait pas partie (il était
  // DÉJÀ posé, au repos par le balisage et à chaque bascule par le code à la main — le compter serait
  // faire passer pour acquis par le ralliement ce qui l'était avant lui) :
  //   * `aria-controls` : le bouton NOMME la région qu'il commande. Ni la version à la main ni le
  //     balisage ne le posaient — le panneau n'avait même pas d'identifiant.
  //   * LA MARQUE D'ÉTAT `.on` sur le bouton. Relevé sur la feuille le 2026-08-30 : AUCUNE règle ne
  //     vise `.fgrouphd.on` ni `.fmetrichd.on` — les 17 règles `.on` de la feuille sont TOUTES portées
  //     par un autre sélecteur (`.sidebar a`, `.subnav .subtab`, `.alertview .agseg`, `.agscope`,
  //     `.srctoggle` ×2, `.evpager .evnum`, `.plmore` ×2, `#dash-play`, `.paneltools .seg button`,
  //     `.caserow`, `#dash-edit`, `#view-share`, `.rmp`, `.pv-chip`, `.favstar`). Elle est donc
  //     INERTE à l'écran : elle ajoute un état lisible par le programme, et rien de visible. Le
  //     chevron reste le seul signal d'état pour l'œil, et il est peint par la feuille depuis
  //     `.collapsed` sur l'ENVELOPPE — le ralliement n'y touche pas.
  //   * UN GAIN QUI N'ÉTAIT PAS DEMANDÉ, ET QUI EST LE PLUS UTILE ICI : l'état annoncé ne se DÉRIVE
  //     plus de la valeur de retour d'une MUTATION. `wrap.classList.toggle('collapsed')` rend un
  //     booléen dans un navigateur, mais RIEN dans le simulacre du harnais ESM (mesuré le 2026-08-30 :
  //     son `classList.toggle` ne retourne pas) — ce pliage-ci n'était donc pas exerçable sur le banc
  //     du dépôt : un témoin y aurait lu « déplié » quoi qu'il arrive. L'ouverture se LIT maintenant
  //     de l'enveloppe (`isOpen`), et le même clic se mesure sur le banc comme dans un navigateur.
  //
  // POURQUOI `observe: false`. L'état est porté par l'ENVELOPPE `.fgroup`, pas par le panneau : il n'y
  // a rien à observer sur `.fgbody`. Et cette liste est REPEINTE à chaque rafraîchissement (30 s) —
  // un observateur par groupe et par rendu s'y accumulerait. C'est la raison même pour laquelle
  // l'option existe (`collapsibleGroup`, core.js, la prend pour la même raison).
  //
  // LE CLAVIER PASSE PAR LE BOUTON NATIF. `.fgrouphd` EST un `<button>` : Entrée et Espace l'activent
  // sans une ligne de code, comme `#rule-collapse` et `#parser-collapse` ralliés avant lui. Le
  // `onkeydown` qui doublait le clic est retiré : garder deux chemins d'activation pour un même geste
  // est exactement le défaut que cette clé ferme. DIFFÉRENCE ASSUMÉE, plutôt que tue : Espace active
  // désormais au RELÂCHEMENT (comportement natif) et non à l'enfoncement.
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  const memoriserLesPlis = () => { try { localStorage.setItem('soc_fresh_collapsed', JSON.stringify([...S.freshCollapsed])); } catch (e) {} };
  b.querySelectorAll('.fgrouphd').forEach(hd => {
    const wrap = hd.closest('.fgroup'); if (!wrap) return;
    const corps = wrap.querySelector('.fgbody'); const cat = wrap.dataset.cat;
    disclosure(hd, corps, {
      observe: false,
      isOpen: () => !wrap.classList.contains('collapsed'),
      open: () => { wrap.classList.remove('collapsed'); S.freshCollapsed.delete('cat:' + cat); memoriserLesPlis(); },
      close: () => { wrap.classList.add('collapsed'); S.freshCollapsed.add('cat:' + cat); memoriserLesPlis(); },
    });
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
  // `P11.18-g` — LE CHOIX D'ORDRE EST MÉMORISÉ AVANT D'ÊTRE APPLIQUÉ : le rendu suivant le relit, donc
  // ni l'auto-rafraîchissement ni un rechargement ne le perdent — c'est ce que le pliage fait déjà.
  const selOrdre = b.querySelector('select[data-ordre]');
  if (selOrdre) selOrdre.onchange = () => { prefSet(CLE_D_ORDRE, selOrdre.value); renderFreshness(); };
  // `P11.21-b` (suite) — LES SÉRIES MÉTRIQUES SE PLIENT PAR LE MÊME GESTE, ET DEUX DIFFÉRENCES SONT
  // GARDÉES PLUTÔT QU'EFFACÉES :
  //   * CET EN-TÊTE N'EST PAS UN BOUTON. C'est un `div.kv` porteur de `role="button"` et de
  //     `tabindex="0"` : RIEN ne l'active nativement, et `disclosure` ne pose qu'un `onclick`. Le
  //     `onkeydown` est donc PORTEUR ici, là où il était un doublon sur `.fgrouphd` — il est conservé,
  //     et il passe par la poignée rendue plutôt que par une seconde bascule écrite à côté.
  //   * `aria-controls` N'EST PAS GAGNÉ ICI, ET C'EST DIT PLUTÔT QUE TU. `disclosure` ne pose ce nom
  //     que depuis l'identifiant du panneau ; `.fmetricbody` n'en a pas, et il n'en reçoit pas. Un
  //     identifiant fixe serait unique par une propriété de la CHARGE UTILE du démon — un seul flux
  //     agrégé `kind:"metric"` (`daemon/src/handlers/freshness.rs`, un `mk("metric", …)`) — que cette
  //     console ne vérifie jamais, alors que `rowOf` en rendrait un par flux métrique et que ce
  //     câblage n'en équipe QUE LE PREMIER (`querySelector`, au singulier, et une seule clé de
  //     pliage `metric-open` pour tous). Nommer une région par un identifiant dont l'unicité dépend
  //     des données d'un autre serait un nom faux le jour où la charge utile change ; le reste est
  //     porté par cette clé.
  const md = b.querySelector('.fmetrichd');
  const wrapMetrique = md && md.closest('.fmetric');
  const corpsMetrique = wrapMetrique && wrapMetrique.querySelector('.fmetricbody');
  if (md && wrapMetrique && corpsMetrique) {
    const pli = disclosure(md, corpsMetrique, {
      observe: false,
      isOpen: () => !wrapMetrique.classList.contains('collapsed'),
      open: () => { wrapMetrique.classList.remove('collapsed'); S.freshCollapsed.add('metric-open'); memoriserLesPlis(); },
      close: () => { wrapMetrique.classList.add('collapsed'); S.freshCollapsed.delete('metric-open'); memoriserLesPlis(); },
    });
    md.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pli.toggle(); } };
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
  // `P11.21-i` — LE PULSE EST LA SURFACE LA PLUS SOUVENT TIRÉE DE TOUT CE LOT (charge VIVE du registre,
  // sur la vue d'arrivée) : c'est ici qu'un relevé tronqué servi comme complet est vu le plus souvent.
  const etat = etatDuReleveServi(d);
  if (d.warming && !etat.cause && !feeds.length) { b.innerHTML = '<div class="muted">… mesure de la fraîcheur des sources en cours</div>'; return; }
  if (etat.refus) { b.innerHTML = '<div class="bad">' + esc(motDuReleveNonLu(etat.cause)) + '</div>'; return; }
  if (!feeds.length) { b.innerHTML = '<div class="muted">aucun feed récent</div>'; return; }
  const head = !d.pipeline_fresh
    ? `<div class="bad" style="font-weight:600;margin-bottom:8px">${ic('warn')} Ingestion en panne — aucune donnée reçue récemment</div>`
    : '';
  // L'aveu précède le compte : les pastilles du pulse comptent les flux LUS, pas ceux qui existent.
  b.innerHTML = bandeauDeReleveIncomplet(etat) + head +
    `<div class="capsum">${summaryPills(feeds)}${renvoi('#freshness-view')}</div>`;
}

// exports du module Fraîcheur/Intégrations (importés par app.js : refresh() + bouton #fresh-refresh).
export { renderIntegrations, renderFreshness, renderFreshnessPulse, renderFreshnessDetail, freshState, countStates, etatDuReleveServi, motDuReleveNonLu, motDuRelevePartiel };

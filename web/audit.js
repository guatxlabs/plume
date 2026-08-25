// audit.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Audit / ledger (lecture seule): journal des mutations hashe (id DESC, admin).
//
// `P11.16-d` — LA VUE DIT CE QU'ELLE MONTRE, ET CE QU'ELLE NE MONTRE PAS.
// Le journal d'intégrité ne se purge pas : il ne fait que grossir. Cette vue le demandait sans aucune
// borne de temps, avec un total qui recomptait toute la table à CHAQUE page et une pagination par
// décalage. Trois choses changent ici, et une seule règle les gouverne : sur cette vue, une ligne
// manquante ne se remarque pas — donc rien ne se retire en silence.
//   * UNE FENÊTRE DE TEMPS, réglable (`#ledger-window`), dont le défaut est `FENETRE_DEFAUT` jours. Elle
//     est NOMMÉE au-dessus du tableau, avec sa date de début. Quand elle MORD — le démon répond
//     `older_outside_window` — la vue le dit et nomme la date de la plus ancienne entrée du journal.
//   * LE TOTAL vient d'un comptage BORNÉ côté démon, et il n'est demandé QU'UNE FOIS par fenêtre
//     (`count=0` sur les pages suivantes) : un total ne bouge pas au fil d'un parcours, et le redemander
//     ferait relire jusqu'au plafond pour un chiffre déjà connu. Sous le plafond il est exact et le pager
//     est numéroté. AU plafond (`total_capped`), on passe `total:-1` au pager partagé : il rend alors
//     « page N » avec des flèches fiables au lieu d'un dernier numéro qui CACHERAIT les pages au-delà du
//     plafond. Le plafond atteint est écrit au-dessus du tableau, avec sa valeur.
//   * LA PAGE SUIVANTE se prend PAR CLÉ (`cursor` = `id` de la dernière ligne rendue), comme le flux
//     d'événements (#28) : un clic sur un NUMÉRO reste un saut par décalage, borné côté démon, et la
//     page atterrie rend son curseur — le parcours séquentiel repart donc par clé.
import { $, api, fmtTs, muted, pagedList, poserLaPlageSurLaCible, poserLeChoixDeDates, LANG } from './core.js';
import { S } from './state.js';
import { loadOperatorAudit } from './multitenant.js';

// Fenêtres offertes, en jours ; `0` = tout l'historique. Le défaut est 30 jours : c'est la rétention
// par défaut des événements, donc la période que l'exploitant a déjà en tête en ouvrant l'audit.
const FENETRES = [7, 30, 90, 365, 0];
const FENETRE_DEFAUT = 30;
let fenetreJours = FENETRE_DEFAUT;
// Curseur permettant d'ATTEINDRE la page i (index = numéro de page 0-based ; `null` = première page).
let curseurs = [null];
// Total de la fenêtre courante, demandé UNE fois puis gardé : il ne bouge pas d'une page à l'autre, et le
// redemander ferait relire jusqu'au plafond de comptage pour un chiffre déjà connu. `null` = pas encore su.
let totalDeLaFenetre = null;
// Le plafond de comptage NOMMÉ par le démon la fois où il a compté (pour que la phrase reste juste sur
// les pages suivantes, qui ne recomptent plus). `null` = jamais atteint sur cette fenêtre.
let plafondDeComptage = null;

// cellule textContent (anti-XSS B7) + title optionnel — pour les colonnes pagedList (render -> Node).
function ledgerCell(txt, title) { const s = document.createElement('span'); s.textContent = txt; if (title) s.title = title; return s; }

// =================================================================================================
// `P11.18-c` — UN CHOIX DE DATES, PARTAGÉ PAR LES VUES QUI BORNENT LE TEMPS.
//
// LE CONSTAT. Les paliers ci-dessus (7 / 30 / 90 / 365 jours) et ceux de la prévention des fuites
// (24 h / 7 j / tout) répondent à « les DERNIERS jours ». Une enquête demande « ENTRE tel jour et tel
// jour », ce qu'aucun palier ne rend. Les paliers RESTENT — ils sont le geste le plus fréquent — et
// choisir un palier RETIRE la plage : un raccourci et une plage sont deux réponses à la même
// question, jamais deux fenêtres superposées.
//
// OÙ CE CHOIX VIT — LE GESTE EST AU POINT COMMUN DEPUIS `P11.18-s`, LA VALEUR EST ENCORE ICI. Le
// contrôle lui-même (lire une saisie, refuser ce qui ne peut pas partir, écrire sur une cible) vit
// dans `web/core.js` et sert QUATRE consommateurs. Ce qui reste ici est la VALEUR partagée par ces
// deux vues-ci, et le sens de ce partage n'est pas arbitraire : c'est la vue dont la ROUTE est la
// plus PAUVRE qui la porte, parce que la plage qu'une route pauvre sait exprimer est un
// SOUS-ENSEMBLE de ce qu'une route riche sait exprimer. Dans l'autre sens, le journal aurait hérité
// d'une plage promettant une borne que sa route ne porte pas.
//
// CE QUE LES DEUX ROUTES ACCEPTENT — LU, PAS SUPPOSÉ (2026-08-25) :
//   * `GET /api/ledger` (`daemon/src/handlers/admin_ui.rs`, `ledger_get`) accepte EXACTEMENT cinq
//     paramètres : `limit`, `offset`, `cursor`, `window_days`, `count`. AUCUN n'est une borne HAUTE.
//     `window_days` est un NOMBRE DE JOURS ; la borne basse en est DÉRIVÉE côté démon
//     (`since = now() - window_days * 86_400`) et la borne haute est l'instant présent, par
//     construction — l'en-tête de la route l'écrit d'ailleurs (« sa borne haute étant l'instant
//     présent »), c'est ce qui rend chaque page bon marché malgré un `ledger(ts)` non indexé.
//   * `POST /api/query` (`daemon/src/handlers/query.rs`) accepte `from` ET `to` (secondes epoch,
//     `0` = pas de borne) ; le compilateur les émet en `ts >= from` et `ts <= to`
//     (`guatx_core::soql`, `table_base`).
//
// CONSÉQUENCE, ASSUMÉE ET DITE. Une plage dont la FIN est antérieure à maintenant est REFUSÉE par les
// deux vues, chacune nommant SA raison mesurée. Elle n'est ni tronquée en silence, ni filtrée après
// coup : sur le journal l'ordre est `id` DÉCROISSANT, donc appliquer une borne haute dans le
// navigateur rendrait VIDES les premières pages (les plus récentes, justement celles au-dessus de la
// fin choisie) et ferait compter au total des entrées que la vue cacherait — c'est-à-dire rendrait un
// refus comme une absence, ce que ce dépôt refuse par ailleurs
// (`check_a_refusal_is_not_rendered_as_an_absence.py`).
//
// CE QUI A ÉTÉ FERMÉ DEPUIS, ET CE QUI RESTE. Côté prévention des fuites, le résidu écrit ici est
// CLOS (`P11.18-r`, 2026-08-25) : `runQ` prend désormais la borne haute EN ARGUMENT, avec un défaut
// qui n'hérite de rien, et ce panneau n'hérite donc plus de l'intervalle de l'Explore. Ce qui a
// remplacé cette raison n'est pas une absence de raison : la plage est PARTAGÉE avec le journal, dont
// la route ne porte aucune borne haute, et c'est ce partage qui gouverne les deux — la route la plus
// pauvre décide de ce que la valeur commune sait exprimer.
// RESTE, NOMMÉ : une borne haute servie par la route du journal la lèverait pour les deux. Elle
// pagine DÉJÀ par `id` décroissant et son `cursor` est un `id` — un `until_ts` traduit côté démon (ou
// un `max_id`) tiendrait dans `LedgerAsk`/`ledger_page_sql` sans changer la forme de la page. C'est
// hors de ce lot, qui ne touche pas au démon.
// =================================================================================================

// LA PLAGE COURANTE, PARTAGÉE PAR LES DEUX VUES : `null` = aucune, les paliers gouvernent. Le partage
// est celui de la VALEUR et pas seulement du code — une enquête porte sur les mêmes jours d'une vue à
// l'autre. Il n'est pas silencieux pour autant, et c'est la condition qui le rend acceptable : CHAQUE
// vue NOMME la plage active au-dessus de ce qu'elle montre. Sans cette obligation, ce serait une borne
// héritée en douce, c'est-à-dire exactement le défaut que ce même lot a mesuré sur `runQ`.
let plageChoisie = null;

// `P11.18-s` — LA CIBLE : le PREMIER des deux paramètres du geste partagé (`web/core.js`). Elle dit
// trois choses et rien de plus — le GRAIN que cet état sait tenir, comment le LIRE, comment
// l'ÉCRIRE. Aucun élément d'interface, aucun refus, aucun nom de vue : ce qui DISTINGUE les
// consommateurs est ici, ce qui leur est COMMUN est au point commun.
// LE GRAIN EST `jour`, ET IL EST DÉRIVÉ, PAS CHOISI : la route du journal ne borne qu'en JOURS
// entiers depuis maintenant, donc cet état ne sait pas tenir un instant plus fin. C'est ce même fait
// qui donne au contrôle des champs `type=date` et une fin qui INCLUT son jour.
const CIBLE_DE_PLAGE = {
  grain: 'jour',
  lire: () => plageChoisie,
  poser: p => { plageChoisie = p; },
};

// CE QUE LA ROUTE DE CETTE VUE SAIT PORTER : le SECOND paramètre. `GET /api/ledger` accepte
// exactement cinq paramètres et AUCUN n'est une borne haute (voir l'en-tête, où ils sont LUS). Une
// plage dont la FIN est antérieure à maintenant ne peut donc pas être envoyée : elle est REFUSÉE, et
// le refus nomme CETTE raison-là. Il est écrit ici parce que c'est ici qu'il est vrai.
const PORTE_DU_JOURNAL = {
  borneHaute: false,
  refus: plage => (LANG === 'en'
    ? 'Range refused: the audit journal route takes only a NUMBER OF DAYS back from now (window_days) and carries no upper bound, so the end you chose (' + plage.texteFin + ') cannot be sent. Applying it here instead would empty the newest pages and count entries the view would hide. What this route accepts: from ' + plage.texteDebut + ' up to now.'
    : "Plage refusée : la route du journal d'audit ne prend qu'un NOMBRE DE JOURS depuis maintenant (window_days) et ne porte aucune borne haute, donc la fin choisie (" + plage.texteFin + ") ne peut pas être envoyée. L'appliquer ici viderait les pages les plus récentes et ferait compter des entrées que la vue cacherait. Ce que cette route accepte : du " + plage.texteDebut + " jusqu'à maintenant."),
};

function plageActive() { return plageChoisie; }

// L'écrivain de la plage partagée, tel que les deux vues le connaissent : il DÉLÈGUE à l'écrivain
// unique du point commun, qui remet au reflet les contrôles posés sur CETTE cible. Écrire
// `plageChoisie` sans passer par là laisserait un contrôle afficher autre chose que ce qui part au
// démon — c'est pour cela que la variable n'est touchée QUE par `CIBLE_DE_PLAGE.poser`.
function poserLaPlage(p) { poserLaPlageSurLaCible(CIBLE_DE_PLAGE, p); }

// La plage -> ce que `GET /api/ledger` sait porter : un NOMBRE DE JOURS. L'arrondi est AU SUPÉRIEUR, et
// c'est un choix écrit : la borne effective (`now - jours*86400`) tombe alors un peu AVANT le jour
// choisi, donc la fenêtre montre un peu PLUS, jamais moins. Sur ce journal une ligne manquante ne se
// remarque pas — élargir se voit, rétrécir non. La borne effective est NOMMÉE au-dessus du tableau.
function joursPourLeJournal(plage, maintenant) { return Math.max(1, Math.ceil((maintenant - plage.debut) / 86400)); }

// Ce que la vue a DEMANDÉ en jours, gardé pour comparer avec ce que le démon a rendu : la route CLAMPE
// `window_days` à son propre plafond (`n.min(LEDGER_WINDOW_MAX_DAYS)`) au lieu de refuser. Le plafond
// n'est donc PAS recopié ici — un second exemplaire pourrirait ; l'écart est DÉRIVÉ de la réponse, et
// c'est lui qui est dit.
let joursDemandes = FENETRE_DEFAUT;

// Le sélecteur de fenêtre est POSÉ PAR CETTE VUE (une seule fois) à côté de celui de taille de page :
// la borne de temps est une propriété du journal, pas une option de mise en page.
function poserLeSelecteurDeFenetre() {
  if ($('#ledger-window')) return;
  const outils = document.querySelector('#ledger-panel .hdtools');
  if (!outils) return;
  const sel = document.createElement('select');
  sel.id = 'ledger-window';
  sel.className = 'picon';
  sel.title = LANG === 'en' ? 'Time window of the audit journal' : "Fenêtre de temps du journal d'audit";
  FENETRES.forEach(n => {
    const o = document.createElement('option');
    o.value = String(n);
    o.textContent = n > 0 ? String(n) + (LANG === 'en' ? ' d' : ' j') : '∞';
    if (n === fenetreJours) o.selected = true;
    sel.appendChild(o);
  });
  // Choisir un PALIER retire la plage : les deux répondent à la même question, et deux fenêtres
  // superposées ne se lisent pas. Le retrait passe par l'écrivain unique, donc les champs de date se
  // vident avec — sans quoi la vue afficherait des dates que la fenêtre envoyée n'a plus.
  sel.addEventListener('change', () => { fenetreJours = parseInt(sel.value, 10) || 0; poserLaPlage(null); loadLedger(); });
  outils.insertBefore(sel, outils.firstChild);
}

// Le contrôle de dates est POSÉ PAR CETTE VUE (une seule fois), au-dessus du tableau : deux champs de
// date n'ont pas leur place dans une barre d'outils d'en-tête, et la phrase de refus qu'ils portent se
// lit avec ce qu'elle refuse. Il vit HORS de `#ledger-body`, comme la ligne de fenêtre : la liste
// paginée remplace tout son contenu à chaque page.
function barreDePlage() {
  if ($('#ledger-range')) return;
  const corps = $('#ledger-body');
  if (!corps || !corps.parentNode) return;
  const c = poserLeChoixDeDates('ledger', CIBLE_DE_PLAGE, PORTE_DU_JOURNAL, () => loadLedger());
  c.barre.id = 'ledger-range';
  c.barre.style.margin = '0 0 9px';
  corps.parentNode.insertBefore(c.barre, corps);
}

// La ligne qui NOMME la fenêtre affichée. Elle vit HORS de `#ledger-body` : la liste paginée remplace
// tout son contenu à chaque page, et une phrase qui dit ce qui est caché ne doit pas disparaître avec.
function ligneDeFenetre() {
  let n = $('#ledger-window-note');
  if (n) return n;
  const corps = $('#ledger-body');
  if (!corps || !corps.parentNode) return null;
  n = muted('');
  n.id = 'ledger-window-note';
  n.setAttribute('role', 'status');
  n.style.margin = '0 0 9px';
  n.style.fontSize = '12px';
  corps.parentNode.insertBefore(n, corps);
  return n;
}

// Ce que la vue DIT d'elle-même, à partir de ce que le démon a répondu. Trois faits, chacun rendu à part :
// la fenêtre regardée ; le fait qu'elle MORD (des entrées existent hors du cadre) ; le fait que le total
// est PLAFONNÉ. Aucun n'est déduit d'un vide : un journal vide et une fenêtre qui coupe sont deux choses.
function direLaFenetre(j) {
  const n = ligneDeFenetre();
  if (!n) return;
  // Le plafond est celui que le démon a NOMMÉ la fois où il a compté ; les pages suivantes ne recomptent
  // pas, donc la phrase ne doit pas dépendre d'un chiffre qu'elles ne portent plus.
  if (j.total_capped) plafondDeComptage = j.total;
  const jours = typeof j.window_days === 'number' ? j.window_days : 0;
  const parts = [];
  if (jours > 0) {
    parts.push((LANG === 'en' ? 'Window: last ' : 'Fenêtre : ') + jours
      + (LANG === 'en' ? ' days' : ' derniers jours')
      + (j.since ? ' (' + (LANG === 'en' ? 'since ' : 'depuis ') + fmtTs(j.since) + ')' : '') + '.');
  } else {
    parts.push(LANG === 'en' ? 'Window: full history.' : "Fenêtre : tout l'historique.");
  }
  // LA PLAGE CHOISIE, NOMMÉE TELLE QU'ELLE A ÉTÉ SAISIE — et la traduction que la route impose. Sans
  // cette phrase, la borne de temps serait partagée entre deux vues sans qu'aucune ne la dise, ce qui
  // est le défaut mesuré ailleurs et non son remède.
  if (plageChoisie) {
    parts.push((LANG === 'en' ? 'Dates chosen: ' : 'Dates choisies : ') + plageChoisie.texteDebut
      + ' → ' + plageChoisie.texteFin
      + (LANG === 'en'
        ? ' — this route bounds in whole DAYS back from now, so the window asked for is '
        : " — cette route borne en JOURS entiers depuis maintenant, la fenêtre demandée vaut donc ")
      + joursDemandes + (LANG === 'en' ? ' days, rounded UP so that nothing before the chosen day is hidden.' : ' jours, arrondis AU SUPÉRIEUR pour ne rien cacher avant le jour choisi.'));
  }
  // LE PLAFOND DU SERVEUR, DÉRIVÉ DE SA RÉPONSE. La route CLAMPE `window_days` au lieu de refuser : la
  // fenêtre rendue peut donc être plus étroite que celle demandée. On ne recopie pas son plafond — on
  // compare ce qui a été demandé à ce qui revient, et on le DIT.
  if (plageChoisie && typeof j.window_days === 'number' && j.window_days !== joursDemandes) {
    parts.push((LANG === 'en' ? 'The server NARROWED this window to ' : 'Le serveur a RESSERRÉ cette fenêtre à ')
      + j.window_days + (LANG === 'en' ? ' days (its own cap) instead of the ' : ' jours (son propre plafond) au lieu des ')
      + joursDemandes + (LANG === 'en' ? ' asked for: entries before ' : ' demandés : les entrées antérieures au ')
      + (j.since ? fmtTs(j.since) : '?') + (LANG === 'en' ? ' are NOT shown.' : ' ne sont PAS affichées.'));
  }
  if (j.older_outside_window) {
    parts.push((LANG === 'en'
      ? 'Older entries exist outside this window and are NOT shown — oldest entry in the journal: '
      : "Des entrées plus anciennes existent hors de cette fenêtre et ne sont PAS affichées — entrée la plus ancienne du journal : ")
      + (j.oldest_ts ? fmtTs(j.oldest_ts) : '?') + '.');
  }
  if (j.total_capped || (j.total == null && totalDeLaFenetre === -1)) {
    parts.push((LANG === 'en' ? 'Exact total not counted beyond ' : 'Total exact non compté au-delà de ')
      + plafondDeComptage
      + (LANG === 'en'
        ? ' entries (server counting cap): paging switches to the arrows, which cover the whole window.'
        : " entrées (plafond de comptage du serveur) : la pagination passe aux flèches, qui parcourent toute la fenêtre."));
  }
  n.textContent = parts.join(' ');
}

async function loadLedger() {
  const wrap = $('#ledger-body'); if (!wrap) return;
  loadOperatorAudit(); // #2c — sous-panneau accès opérateur (multi-tenant only ; masqué/inerte en mode 0)
  poserLeSelecteurDeFenetre();
  barreDePlage();
  curseurs = [null];   // toute (re)construction repart de la première page : un curseur d'une autre fenêtre ne veut rien dire
  totalDeLaFenetre = null;   // …et un total d'une autre fenêtre non plus
  plafondDeComptage = null;
  // La fenêtre en jours est FIGÉE pour tout ce parcours. La recalculer page par page la ferait glisser
  // d'un jour au passage de minuit, et le total comme les curseurs porteraient alors sur deux fenêtres.
  joursDemandes = plageChoisie ? joursPourLeJournal(plageChoisie, Math.floor(Date.now() / 1000)) : fenetreJours;
  pagedList(wrap, {
    mode: 'server',
    pageSize: S.LEDGER_LIMIT,
    emptyText: "aucune entrée d'audit",
    columns: [
      { key: 'id', label: '#', render: en => String(en.id) },
      { key: 'ts', label: 'Horodatage', render: en => ledgerCell(fmtTs(en.ts), en.ts ? String(en.ts) : '') },
      { key: 'kind', label: 'Type', render: en => ledgerCell(en.kind || '') },
      { key: 'detail', label: 'Détail', render: en => ledgerCell(en.detail || '', en.detail || '') },
      { key: 'hash', label: 'Empreinte', render: en => { const h = en.hash || ''; return ledgerCell(h ? h.slice(0, 16) + '…' : '', h); } },
    ],
    fetchPage: async ({ limit, offset }) => {
      const page = limit > 0 ? Math.round(offset / limit) : 0;
      const cur = curseurs[page];
      let url = '/ledger?limit=' + limit + '&window_days=' + joursDemandes;
      if (cur != null) url += '&cursor=' + cur;           // page atteinte PAR CLÉ (parcours séquentiel)
      else if (offset > 0) url += '&offset=' + offset;    // saut à un NUMÉRO : décalage, borné côté démon
      if (totalDeLaFenetre !== null) url += '&count=0';   // total déjà su pour CETTE fenêtre : ne pas le refaire compter
      // UN REFUS N'EST PAS UN VIDE, ET IL N'EST PAS NON PLUS UNE FENÊTRE. Sur échec, la phrase qui décrit
      // la fenêtre est EFFACÉE (elle décrirait des données qu'on n'a pas reçues) et l'erreur remonte telle
      // quelle : `pagedList` rend « erreur : … » à la place du tableau, jamais « aucune entrée d'audit ».
      let j;
      try { j = await api(url); }
      catch (e) { const n = ligneDeFenetre(); if (n) n.textContent = ''; throw e; }
      curseurs[page + 1] = j.has_more ? j.next_cursor : null;
      direLaFenetre(j);
      // Total PLAFONNÉ -> `-1` : le pager partagé passe en « page N » avec des flèches fiables plutôt que
      // de numéroter jusqu'à un dernier numéro qui rendrait les pages suivantes inatteignables.
      if (typeof j.total === 'number') totalDeLaFenetre = j.total_capped ? -1 : j.total;
      return { rows: j.entries || [], total: totalDeLaFenetre === null ? 0 : totalDeLaFenetre };
    },
  });
}


// `P11.18-s` — CE QUE CETTE VUE EXPORTE POUR L'AUTRE, ET CE QU'ELLE N'EXPORTE PLUS. Le CHOIX DE
// DATES n'est plus ici : il est au point commun (`web/core.js`), avec son lecteur pur, ses refus et
// son écrivain, et il sert quatre consommateurs. Ce qui part encore d'ici est ce qui appartient
// vraiment à ces deux vues : la CIBLE où leur plage se pose — la valeur partagée — et les deux
// gestes qui la lisent et l'écrivent. `joursPourLeJournal` reste PURE et exportée pour être éprouvée
// sans document ni réseau : c'est la traduction que la route de CETTE vue impose, elle n'appartient
// donc à aucune autre.
export { loadLedger, CIBLE_DE_PLAGE, joursPourLeJournal, plageActive, poserLaPlage };

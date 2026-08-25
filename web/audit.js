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
import { $, api, fmtTs, muted, pagedList, LANG } from './core.js';
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
// OÙ CE CHOIX VIT, ET POURQUOI ICI PLUTÔT QU'AU POINT COMMUN. Un composant partagé par deux vues
// appartient à `web/core.js`. Il n'y est pas, et c'est dit plutôt que sous-entendu : cette vue-ci
// l'EXPORTE et `web/dataaccess.js` l'IMPORTE. Le sens du partage n'est pas arbitraire — c'est la vue
// dont la ROUTE est la plus PAUVRE qui le porte, parce que la plage qu'une route pauvre sait exprimer
// est un SOUS-ENSEMBLE de ce qu'une route riche sait exprimer. Dans l'autre sens, le journal aurait
// hérité d'un contrôle promettant une borne que sa route ne porte pas. La forme recommandée reste
// celle du point commun ; elle est décrite en fin de bloc.
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
// CE QUI FERMERAIT LE RÉSIDU, ÉCRIT PLUTÔT QUE TU. Côté journal, une borne haute servie par la route :
// elle pagine DÉJÀ par `id` décroissant et son `cursor` est un `id` — un `until_ts` traduit côté démon
// (ou un `max_id`) tiendrait dans `LedgerAsk`/`ledger_page_sql` sans changer la forme de la page.
// Côté prévention des fuites, la route accepte déjà `to` : il manque au fabricant partagé `runQ`
// (`web/viz.js`) le moyen de le POSER — il le prend aujourd'hui de l'intervalle de l'Explore.
// Les deux sont hors de ce lot.
//
// LA FORME RECOMMANDÉE, SI LE POINT COMMUN S'OUVRE : `core.js` porte déjà `makePager`/`pagedList`,
// c'est-à-dire des fabriques d'interface partagées. Le choix de temps a la même nature. Mieux : le
// geste EXISTE DÉJÀ, mal placé — `openRangeModal` (`web/app.js`) offre paliers ET intervalle absolu,
// avec ses deux refus (« Dates invalides. », « Le début doit précéder la fin. ») et son style
// (`.rmgrid`/`.rmp`/`.rmabs`, `web/style.css`), mais il n'est pas exporté et il écrit dans
// `S.zoomRange`, l'état de l'Explore et des Dashboards. La forme juste est de le LEVER dans `core.js`
// en le paramétrant par sa CIBLE (l'état où la plage se pose) et par ce que la route de l'appelant
// SAIT porter, puis de lui faire servir les quatre consommateurs : `#range` (dashboards), `#qrange`
// (Explore), le journal d'audit et la prévention des fuites. Ce lot ne pouvant toucher ni `core.js`
// ni `app.js` ni `viz.js`, il pose le contrat ici et le nomme.
// =================================================================================================

// LA PLAGE COURANTE, PARTAGÉE PAR LES DEUX VUES : `null` = aucune, les paliers gouvernent. Le partage
// est celui de la VALEUR et pas seulement du code — une enquête porte sur les mêmes jours d'une vue à
// l'autre. Il n'est pas silencieux pour autant, et c'est la condition qui le rend acceptable : CHAQUE
// vue NOMME la plage active au-dessus de ce qu'elle montre. Sans cette obligation, ce serait une borne
// héritée en douce, c'est-à-dire exactement le défaut que ce même lot a mesuré sur `runQ`.
let plageChoisie = null;
// Les contrôles POSÉS, par clé de vue — une vue repeinte REMPLACE le sien (aucune accumulation). Ils
// servent à REFLÉTER la plage : un changement fait ailleurs ne doit pas laisser des dates affichées que
// la fenêtre envoyée n'a plus.
const controlesPoses = new Map();

function plageActive() { return plageChoisie; }

// LE SEUL ÉCRIVAIN de la plage partagée. Écrire ailleurs laisserait un contrôle afficher autre chose
// que ce qui part au démon.
function poserLaPlage(p) {
  plageChoisie = p;
  controlesPoses.forEach(c => {
    c.debut.value = plageChoisie ? plageChoisie.texteDebut : '';
    c.fin.value = plageChoisie ? plageChoisie.texteFin : '';
  });
}

// Un jour du calendrier, tel qu'un champ `type=date` le rend (« AAAA-MM-JJ »), en secondes epoch à
// l'heure LOCALE de l'analyste : il choisit un jour de SON calendrier, pas un instant UTC.
// `finDeJournee` -> la DERNIÈRE seconde du jour choisi (la fin d'un jour INCLUT ce jour).
// `null` = illisible. Un jour inexistant (2026-02-31) est REPORTÉ par `Date` sur le mois suivant : on
// le refuse au lieu de laisser cette correction silencieuse passer pour un choix.
function jourEnSecondes(texte, finDeJournee) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(texte == null ? '' : texte).trim());
  if (!m) return null;
  const a = Number(m[1]), mo = Number(m[2]), j = Number(m[3]);
  const d = new Date(a, mo - 1, j, 0, 0, 0, 0);
  if (d.getFullYear() !== a || d.getMonth() !== mo - 1 || d.getDate() !== j) return null;
  if (!finDeJournee) return Math.floor(d.getTime() / 1000);
  d.setDate(d.getDate() + 1);
  return Math.floor(d.getTime() / 1000) - 1;
}

// LE SEUL LECTEUR d'une plage choisie — fonction PURE (deux textes + un instant -> une plage OU un
// refus), ce qui la rend éprouvable sans document ni réseau. Elle ne CORRIGE jamais : chaque saisie
// qu'elle ne sait pas lire produit un REFUS qui dit POURQUOI, et aucune fenêtre ne part. Rendre une
// plage « la plus proche » d'une saisie fautive serait répondre à une question que personne n'a posée.
function lirePlageChoisie(texteDebut, texteFin, maintenant) {
  const td = String(texteDebut == null ? '' : texteDebut).trim();
  const tf = String(texteFin == null ? '' : texteFin).trim();
  if (!td || !tf) {
    return { refus: (LANG === 'en' ? 'A range needs TWO dates — a start and an end. Missing: ' : 'Une plage demande DEUX dates — un début et une fin. Manque : ')
      + (!td ? (LANG === 'en' ? 'the start' : 'le début') : '') + (!td && !tf ? (LANG === 'en' ? ' and ' : ' et ') : '')
      + (!tf ? (LANG === 'en' ? 'the end' : 'la fin') : '') + '.' };
  }
  const debut = jourEnSecondes(td, false), fin = jourEnSecondes(tf, true);
  if (debut == null || fin == null) {
    return { refus: (LANG === 'en' ? 'Unreadable date: ' : 'Date illisible : ')
      + (debut == null ? td : tf)
      + (LANG === 'en' ? '. A calendar day is expected, written YYYY-MM-DD. Nothing was sent.' : '. Un jour du calendrier est attendu, écrit AAAA-MM-JJ. Rien n\'a été envoyé.') };
  }
  if (debut > fin) {
    return { refus: (LANG === 'en' ? 'Reversed range: the start (' : 'Plage inversée : le début (') + td
      + (LANG === 'en' ? ') is AFTER the end (' : ') est APRÈS la fin (') + tf
      + (LANG === 'en' ? '). The two dates are kept as typed and nothing was sent — swapping them here would answer a question nobody asked.' : "). Les deux dates restent telles qu'elles ont été saisies et rien n'a été envoyé — les échanger ici répondrait à une question que personne n'a posée.") };
  }
  if (debut > maintenant) {
    return { refus: (LANG === 'en' ? 'Start date in the future: ' : 'Date de début dans le futur : ') + td
      + (LANG === 'en' ? '. Nothing has been recorded after now, so this range can only be empty — and an empty window reads as an absence. Nothing was sent.' : ". Rien n'est enregistré après maintenant, donc cette plage ne peut être que vide — et une fenêtre vide se lit comme une absence. Rien n'a été envoyé.") };
  }
  return { debut, fin, texteDebut: td, texteFin: tf };
}

// La borne HAUTE choisie couvre-t-elle l'instant présent ? C'est la SEULE question qui décide si une
// plage est exprimable par les deux chemins de ce lot (voir l'en-tête : le journal ne borne qu'en bas,
// et `runQ` ne laisse pas poser `to`). Une fin posée au jour courant la couvre : `jourEnSecondes`
// rend la DERNIÈRE seconde du jour.
function borneHauteCouvreMaintenant(plage, maintenant) { return plage.fin >= maintenant; }

// LE CONTRÔLE partagé : deux champs de date, un bouton qui APPLIQUE, un bouton qui RETIRE, et UNE ligne
// qui porte le refus. Rien ne part tant qu'une saisie est refusée, et la plage précédente reste intacte
// — un refus ne modifie pas la fenêtre, il explique pourquoi elle n'a pas bougé.
// `cle` : la vue qui pose (une seule inscription par vue). `surChangement` n'est rappelé QUE lorsque la
// plage a effectivement changé. `raisonBorneHaute(plage)` : la phrase, propre à la vue appelante, qui
// dit pourquoi SON chemin ne porte pas de borne haute — écrite là où elle est vraie, pas ici.
function poserLeChoixDeDates(cle, surChangement, raisonBorneHaute) {
  const barre = document.createElement('div');
  barre.className = 'rmabs';
  barre.setAttribute('role', 'group');
  barre.setAttribute('aria-label', LANG === 'en' ? 'Exact dates (start and end)' : 'Dates exactes (début et fin)');
  const champ = texte => {
    const l = document.createElement('label');
    const i = document.createElement('input');
    i.type = 'date';
    l.append(texte, i);
    barre.appendChild(l);
    return i;
  };
  const debut = champ(LANG === 'en' ? 'From (day)' : 'Du (jour)');
  const fin = champ(LANG === 'en' ? 'To (day)' : 'Au (jour)');
  const appliquer = document.createElement('button');
  appliquer.type = 'button';
  appliquer.className = 'btn btn-sm';
  appliquer.textContent = LANG === 'en' ? 'Apply these dates' : 'Appliquer ces dates';
  const retirer = document.createElement('button');
  retirer.type = 'button';
  retirer.className = 'linklike';
  retirer.textContent = LANG === 'en' ? 'Back to the shortcut' : 'Revenir au raccourci';
  // La ligne de refus occupe toute la largeur de la barre : une phrase qui explique un refus ne se lit
  // pas coincée entre deux champs. `hidden` tant qu'il n'y a rien à dire — jamais un vide qui se
  // confondrait avec un espace réservé.
  const refus = document.createElement('div');
  refus.className = 'bad';
  refus.setAttribute('role', 'alert');
  refus.style.cssText = 'flex-basis:100%;margin:4px 0 0';
  refus.hidden = true;
  const direLeRefus = texte => { refus.textContent = texte; refus.hidden = !texte; };
  // Retoucher une date EFFACE le refus : il porte sur ce qui était saisi, pas sur ce qui l'est.
  debut.addEventListener('input', () => direLeRefus(''));
  fin.addEventListener('input', () => direLeRefus(''));
  appliquer.addEventListener('click', () => {
    const maintenant = Math.floor(Date.now() / 1000);
    const lue = lirePlageChoisie(debut.value, fin.value, maintenant);
    if (lue.refus) { direLeRefus(lue.refus); return; }
    if (!borneHauteCouvreMaintenant(lue, maintenant)) { direLeRefus(raisonBorneHaute(lue)); return; }
    direLeRefus('');
    poserLaPlage(lue);
    surChangement();
  });
  retirer.addEventListener('click', () => {
    debut.value = ''; fin.value = ''; direLeRefus('');
    if (plageChoisie) { poserLaPlage(null); surChangement(); }
  });
  barre.append(appliquer, retirer, refus);
  const controle = { barre, debut, fin, appliquer, retirer, refus, direLeRefus };
  controlesPoses.set(cle, controle);
  debut.value = plageChoisie ? plageChoisie.texteDebut : '';
  fin.value = plageChoisie ? plageChoisie.texteFin : '';
  return controle;
}

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
  const c = poserLeChoixDeDates('ledger', () => loadLedger(), plage => (LANG === 'en'
    ? 'Range refused: the audit journal route takes only a NUMBER OF DAYS back from now (window_days) and carries no upper bound, so the end you chose (' + plage.texteFin + ') cannot be sent. Applying it here instead would empty the newest pages and count entries the view would hide. What this route accepts: from ' + plage.texteDebut + ' up to now.'
    : "Plage refusée : la route du journal d'audit ne prend qu'un NOMBRE DE JOURS depuis maintenant (window_days) et ne porte aucune borne haute, donc la fin choisie (" + plage.texteFin + ") ne peut pas être envoyée. L'appliquer ici viderait les pages les plus récentes et ferait compter des entrées que la vue cacherait. Ce que cette route accepte : du " + plage.texteDebut + " jusqu'à maintenant."));
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


// `P11.18-c` — CE QUE CETTE VUE EXPORTE POUR L'AUTRE, ET POURQUOI C'EST ÉCRIT ICI. Le choix de dates
// n'appartient pas au journal d'audit : il appartient au point commun. Faute de pouvoir l'y poser, il
// vit dans la vue dont la route est la plus pauvre et `web/dataaccess.js` l'importe (voir l'en-tête du
// bloc `P11.18-c`). `lirePlageChoisie` et `jourEnSecondes` sont PURES et exportées pour être éprouvées
// sans document ni réseau — c'est le seul moyen de tenir « une saisie refusée dit pourquoi » autrement
// que par la pose d'un écouteur, qui ne prouve rien du chemin réel de la frappe.
export { loadLedger, jourEnSecondes, lirePlageChoisie, borneHauteCouvreMaintenant, joursPourLeJournal, plageActive, poserLaPlage, poserLeChoixDeDates };

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
// `P10.21-c` — LA SUITE D'UNE PAGE DU JOURNAL SE LIT PAR LE DISCRIMINANT DU PANNEAU DE RÉTENTION, pas par
// un second. Les deux seules vues qui lisent `GET /api/ledger` sont celle-ci et `web/retention.js` : la
// même clé du démon y a les MÊMES trois issues, et deux lecteurs écrits à part divergeraient sur le seul
// cas qui compte, la clé absente. `P10.21-x` — ce discriminant vit désormais au point commun
// (`web/core.js`), que les deux vues importaient déjà : l'arête `audit.js` → `retention.js`, qui fermait un
// cycle direct avec l'import inverse (`celluleDeGenre`), n'existe plus, et aucun module n'entre ni ne
// sort de la fermeture des imports (`retention.js` y reste par `navigation.js`).
import { $, api, cleDeLaSuiteServie, fmtTs, muted, pagedList, LANG } from './core.js';
import { poserLaPlageSurLaCible, poserLeChoixDeDates } from './plage_de_dates.js';
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
// `P10.20-q` — LE REGISTRE DISTINGUE UN VERDICT CONSERVÉ D'UN VERDICT QU'IL N'A PAS RELU.
//
// CE QUE LE DÉMON ÉCRIT. Quand la clôture gardée d'une action n'a rien écrit, `respond_run`
// (daemon/src/handlers/actions.rs) relit le verdict CONSERVÉ et pose une ligne de registre. Le repli
// `unwrap_or_default()` rendait `""` : la ligne disait « verdict `` déjà posé, conservé » aussi bien
// pour une ligne DISPARUE que pour une lecture qui N'AVAIT PAS EU LIEU. La relecture est désormais
// typée, et la lecture non faite porte son PROPRE genre, `action.exec.verdict-non-relu`, distinct du
// `action.exec.verdict-conserve` d'un verdict établi.
//
// CE QUE CETTE VUE EN FAISAIT. La colonne « Type » rendait le genre TEL QUEL. Le seul genre que le
// démon ait créé pour dire qu'il ne sait pas arrivait donc à l'écran comme un jeton parmi d'autres, à
// un caractère de son voisin — et un jeton de machine n'est pas une phrase : rien ne disait que cette
// ligne-là, seule de tout le registre, n'établit AUCUN verdict.
//
// CE QUE LA VUE EN FAIT MAINTENANT, ET CE QU'ELLE GARDE. Le genre est rendu par sa PHRASE, dans le
// registre de l'alarme, et le jeton brut reste À CÔTÉ : la recherche de cette liste dérive son texte
// des cellules RENDUES (`pagedList`, web/core.js), donc le jeton reste ce qu'on tape pour retrouver
// ces lignes, et c'est aussi lui qu'on recopie dans un rapport. Tout autre genre est rendu tel quel.
//
// CE QUE CETTE VUE NE TIENT PAS : elle ne FILTRE pas par genre — sa seule sélection est la recherche
// de la page servie, et la porter à la route a été mesuré et refusé (voir `loadLedger`). Le genre
// distinct reste donc cherchable, pas filtrable.
// =================================================================================================
// `P10.20-v`, lu ici sous `P10.20-y` — LE SECOND GENRE QUI DIT QU'UN FAIT ANNONCÉ N'A PAS EU LIEU.
// `netban.non-arme` est posé par `action_approve` et par le responder (daemon/src/handlers/actions.rs)
// ainsi que par la boucle de playbooks (daemon/src/handlers/playbooks.rs) quand l'écriture de la ligne
// de blocage a ÉCHOUÉ. C'est le seul genre du registre qui dise qu'un blocage ANNONCÉ n'existe pas :
// à un tiret de `netban.add`, qui dit l'inverse, et lu sur la vue où l'on vient vérifier qu'une adresse
// est bien bloquée. Rendu en jeton, il se confondait avec la ligne d'un ban posé.
const GENRES_DE_REGISTRE_MOTS = {
  'action.exec.verdict-non-relu': {
    fr: "Verdict conservé NON RELU — cette ligne ne dit PAS lequel a été conservé",
    en: 'Kept verdict NOT RE-READ — this line does NOT say which one was kept' },
  'netban.non-arme': {
    fr: "Blocage NON ARMÉ — l'adresse de cette ligne n'est PAS bloquée : la ligne du ban n'a pas pu être écrite, et rien ne la bloque",
    en: 'Block NOT ARMED — the address on this line is NOT blocked: the ban line could not be written, and nothing blocks it' },
};
// Fonction PURE (un genre -> une phrase, ou rien), pour être éprouvée sans document ni réseau.
function motDuGenreDeRegistre(kind) {
  const mots = GENRES_DE_REGISTRE_MOTS[kind];
  if (!mots) return '';
  return LANG === 'en' ? mots.en : mots.fr;
}
// La cellule du genre : deux nœuds quand la vue sait le nommer — la phrase posée au puits, le jeton du
// démon à côté —, un seul nœud sinon, exactement comme avant.
function celluleDeGenre(kind) {
  const phrase = motDuGenreDeRegistre(kind);
  if (!phrase) return ledgerCell(kind);
  const cellule = document.createElement('span'); cellule.className = 'bad';
  const dit = document.createElement('span'); dit.textContent = phrase;
  const jeton = document.createElement('code'); jeton.className = 'muted'; jeton.textContent = kind;
  cellule.append(dit, ' ', jeton);
  return cellule;
}

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
// dans `web/core.js` et sert LES DEUX VUES QUI POSENT LA BARRE — celle-ci et la prévention des fuites.
// Le chiffre qui vivait ici (« QUATRE ») comptait la famille entière des gestes de plage, modale
// comprise, et aucune garde ne le suivait ; la mesure du 2026-08-29 en donne DEUX pour CE geste, et un
// compte qui n'est plus recopié ne peut plus dériver. Ce qui reste ici est la VALEUR partagée par ces
// deux vues-ci, et le sens de ce partage n'est pas arbitraire : c'est la vue dont la ROUTE est la
// plus PAUVRE qui la porte, parce que la plage qu'une route pauvre sait exprimer est un
// SOUS-ENSEMBLE de ce qu'une route riche sait exprimer. Dans l'autre sens, le journal aurait hérité
// d'une plage promettant une borne que sa route ne porte pas.
//
// CE QUE LES DEUX ROUTES ACCEPTENT — LU, PAS SUPPOSÉ (2026-08-25, revu le 2026-09-08) :
//   * `GET /api/ledger` (`daemon/src/handlers/admin_ui.rs`, `ledger_get`) accepte `limit`, `offset`,
//     `cursor`, `window_days`, `count` — et, depuis `P11.18-t`, `until_ts` : la borne HAUTE, INCLUSE,
//     en secondes epoch. `window_days` reste un NOMBRE DE JOURS ; la borne basse en est DÉRIVÉE côté
//     démon (`since = now() - window_days * 86_400`). Sans `until_ts`, la borne haute est l'instant
//     présent, par construction ; avec, le démon la RÉPÈTE dans sa réponse pour que la vue la dise.
//   * `POST /api/query` (`daemon/src/handlers/query.rs`) accepte `from` ET `to` (secondes epoch,
//     `0` = pas de borne) ; le compilateur les émet en `ts >= from` et `ts <= to`
//     (`guatx_core::soql`, `table_base`).
//
// CE QUI ÉTAIT REFUSÉ, ET NE L'EST PLUS (`P11.18-t`, 2026-09-08). Une plage dont la FIN est antérieure
// à maintenant était REFUSÉE par les deux vues : la route du journal ne portait aucune borne haute, et
// la valeur de plage étant PARTAGÉE, la route la plus pauvre décidait de ce que la valeur commune
// savait exprimer — poser une fin passée ici aurait fait afficher au journal une fenêtre qu'il n'avait
// pas. La route porte désormais `until_ts` ; les deux vues envoient donc la fin choisie, chacune par
// son paramètre. Ce qui reste vrai : on ne filtre JAMAIS dans le navigateur pour compenser une borne
// que la route ne porterait pas — l'ordre étant `id` DÉCROISSANT, cela viderait les premières pages et
// ferait compter des entrées cachées, un refus rendu comme une absence
// (`check_a_refusal_is_not_rendered_as_an_absence.py`).
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

// CE QUE LA ROUTE DE CETTE VUE SAIT PORTER : le SECOND paramètre. `GET /api/ledger` porte une borne
// haute (`until_ts`, `P11.18-t`) : une fin antérieure à maintenant PART, elle n'est plus refusée.
// La porte n'a donc plus de phrase de refus à donner — le point commun ne l'appelle que quand la
// route ne porte pas la borne.
const PORTE_DU_JOURNAL = { borneHaute: true };

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

// =================================================================================================
// `P10.21-c` — CETTE VUE SE SERVAIT DE `has_more` SANS JAMAIS DIRE EN MOTS QU'UNE SUITE EXISTE PEUT-ÊTRE.
//
// CE QUE LE DÉMON SERT, ET CE QUE ÇA VEUT DIRE EXACTEMENT. `ledger_page` (daemon/src/handlers/admin_ui.rs)
// pose `next_cursor` quand la page rend EXACTEMENT autant de lignes qu'elle en demandait, et `has_more`
// vaut `!next_cursor.is_null()` : « la page est PLEINE et un curseur de suite est servi ». Ce n'est PAS
// « d'autres entrées existent » — une fenêtre dont le nombre d'entrées est un multiple exact de la taille
// de page le rend vrai sur sa dernière page. La phrase ci-dessous dit ce que la clé dit, et pas un mot de plus.
//
// CE QUE LA VUE EN FAISAIT. La clé ne décidait que du CURSEUR de la page suivante (par clé plutôt que
// par décalage). La flèche « suivant » du pager partagé ne la lit pas : elle suit le TOTAL quand il est
// exact, la page PLEINE quand il est plafonné — et, sans total servi, `pagedList` ne rend AUCUN pager,
// page pleine ou non. Rien, à l'écran, ne distinguait donc « le démon dit qu'une suite peut venir », « il
// dit qu'il n'y en a pas » et « il n'a rien dit ».
//
// LES TROIS ISSUES, CELLES DU PANNEAU DE RÉTENTION. Le discriminant est le sien (importé plus haut) ; les
// MOTS sont ceux de cette vue, parce qu'ils parlent d'une page du journal et non d'un changement de
// rétention. « Aucune suite » est un silence ÉCRIT : la page n'était pas pleine, le pager et la phrase de
// fenêtre suffisent. La clé ABSENTE ou d'un autre type est AVOUÉE, dans le registre de l'alarme : un
// silence du démon ne se lit pas comme la fin du journal.
// =================================================================================================
const MOTS_DE_LA_SUITE_DU_JOURNAL = {
  il_en_existe_peut_etre_d_autres: {
    fr: " Cette page est PLEINE — {nombre} entrées, autant que demandé — et le démon sert un curseur de suite : d'autres entrées de cette fenêtre peuvent la suivre. Ce curseur ne dit pas qu'il y en a ; il dit que la page n'a pas pu en montrer davantage.",
    en: ' This page is FULL — {nombre} entries, as many as requested — and the daemon serves a continuation cursor: more entries of this window may follow it. That cursor does not say there are any; it says the page could not show more.' },
  // Les deux faces sont vides À DESSEIN : l'entrée existe pour que ce silence soit un choix écrit.
  aucune_suite: { fr: '', en: '' },
  suite_non_dite: {
    fr: " Le démon n'a PAS dit si d'autres entrées suivent cette page : la fin du tableau n'établit donc pas la fin du journal dans cette fenêtre.",
    en: ' The daemon did NOT say whether more entries follow this page: the end of the table therefore does not establish the end of the journal within this window.' },
};
const motDeLaSuiteDuJournal = (cle, nombre) =>
  (LANG === 'en' ? MOTS_DE_LA_SUITE_DU_JOURNAL[cle].en : MOTS_DE_LA_SUITE_DU_JOURNAL[cle].fr).replace('{nombre}', String(nombre));

// Ce que la vue DIT d'elle-même, à partir de ce que le démon a répondu. Quatre faits, chacun rendu à part :
// la fenêtre regardée ; le fait qu'elle MORD (des entrées existent hors du cadre) ; le fait que le total
// est PLAFONNÉ ; et ce que le démon dit de la SUITE de cette page. Aucun n'est déduit d'un vide : un
// journal vide et une fenêtre qui coupe sont deux choses.
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
        ? ' — this route bounds the START in whole DAYS back from now, so the window asked for is '
        : " — cette route borne le DÉBUT en JOURS entiers depuis maintenant, la fenêtre demandée vaut donc ")
      + joursDemandes + (LANG === 'en' ? ' days, rounded UP so that nothing before the chosen day is hidden' : ' jours, arrondis AU SUPÉRIEUR pour ne rien cacher avant le jour choisi')
      // LA FIN, TELLE QUE LE DÉMON L'A APPLIQUÉE — lue dans sa réponse, jamais recopiée de la saisie.
      + (typeof j.until_ts === 'number'
        ? (LANG === 'en' ? '; the END is applied by the server up to ' : ' ; la FIN est appliquée par le serveur jusqu\'au ') + fmtTs(j.until_ts) + (LANG === 'en' ? ' (included).' : ' (inclus).')
        : (LANG === 'en' ? '; the server applied NO end bound.' : ' ; le serveur n\'a appliqué AUCUNE borne de fin.')));
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
  // `P10.21-c` — LA SUITE DE LA PAGE, POSÉE AU PUITS (`textContent`) APRÈS LA PHRASE DE FENÊTRE. Elle vit
  // dans la même ligne, hors de `#ledger-body` que la liste paginée remplace ; l'affectation ci-dessus
  // retire celle de la page précédente, donc rien ne s'empile d'une page à l'autre.
  const cleDeLaSuite = cleDeLaSuiteServie(j);
  const motDeLaSuite = motDeLaSuiteDuJournal(cleDeLaSuite, (j.entries || []).length);
  if (motDeLaSuite) {
    const suite = document.createElement('span');
    suite.className = cleDeLaSuite === 'suite_non_dite' ? 'bad' : 'muted';
    suite.dataset.suiteDuJournal = cleDeLaSuite;
    suite.textContent = motDeLaSuite;
    n.append(suite);
  }
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
    // `P11.18-x` — la recherche est ACTIVÉE telle quelle : la fabrique dit d'elle-même qu'elle ne
    // couvre que la page servie. La porter à la route a été mesuré et REFUSÉ le 2026-09-09 : la table
    // `ledger` n'a d'index que sur sa clé, une recherche serveur sur `detail` serait un parcours
    // complet d'un journal de plusieurs millions de lignes, et un index plein-texte exigerait une
    // migration de schéma — une porte à sens unique.
    recherche: true, storeKey: 'audit',
    emptyText: "aucune entrée d'audit",
    columns: [
      { key: 'id', label: '#', render: en => String(en.id) },
      { key: 'ts', label: 'Horodatage', render: en => ledgerCell(fmtTs(en.ts), en.ts ? String(en.ts) : '') },
      { key: 'kind', label: 'Type', render: en => celluleDeGenre(en.kind || '') },
      { key: 'detail', label: 'Détail', render: en => ledgerCell(en.detail || '', en.detail || '') },
      { key: 'hash', label: 'Empreinte', render: en => { const h = en.hash || ''; return ledgerCell(h ? h.slice(0, 16) + '…' : '', h); } },
    ],
    fetchPage: async ({ limit, offset }) => {
      const page = limit > 0 ? Math.round(offset / limit) : 0;
      const cur = curseurs[page];
      let url = '/ledger?limit=' + limit + '&window_days=' + joursDemandes;
      if (plageChoisie) url += '&until_ts=' + plageChoisie.fin;   // `P11.18-t` : la fin choisie PART, incluse (dernière seconde du jour)
      if (cur != null) url += '&cursor=' + cur;           // page atteinte PAR CLÉ (parcours séquentiel)
      else if (offset > 0) url += '&offset=' + offset;    // saut à un NUMÉRO : décalage, borné côté démon
      if (totalDeLaFenetre !== null) url += '&count=0';   // total déjà su pour CETTE fenêtre : ne pas le refaire compter
      // UN REFUS N'EST PAS UN VIDE, ET IL N'EST PAS NON PLUS UNE FENÊTRE. Sur échec, la phrase qui décrit
      // la fenêtre est EFFACÉE (elle décrirait des données qu'on n'a pas reçues) et l'erreur remonte telle
      // quelle : `pagedList` rend « erreur : … » à la place du tableau, jamais « aucune entrée d'audit ».
      let j;
      try { j = await api(url); }
      catch (e) { const n = ligneDeFenetre(); if (n) n.textContent = ''; throw e; }
      // `P10.20-a` — UN JOURNAL NON LU N'EST PAS UN JOURNAL VIERGE. `ledger_page`
      // (daemon/src/handlers/admin_ui.rs) sert, en 200, la forme ENTIÈRE de la page — `entries: []`,
      // `has_more: false`, les bornes de fenêtre — et y AJOUTE `ok:false`, `lecture_non_faite:true` et la
      // cause sous `error`. `api()` ne jette que sur `!r.ok` : la cause arrivait donc dans un corps lu comme
      // un succès, `j.entries || []` en refaisait une absence, et la page rendait « aucune entrée d'audit »
      // — sur un journal d'audit, la phrase la plus rassurante qui soit : aucun geste tracé. La cause remonte
      // par le MÊME chemin qu'un rejet (la phrase de fenêtre effacée, l'erreur telle quelle au rendu partagé).
      if (j && j.error) { const n = ligneDeFenetre(); if (n) n.textContent = ''; throw new Error(String(j.error).trim()); }
      // Le curseur suit la MÊME lecture que la phrase : une valeur que la vue n'avouerait pas comme une
      // suite ne décide pas non plus de la page suivante (pour un booléen, rien ne change).
      const cleDeLaSuite = cleDeLaSuiteServie(j);
      curseurs[page + 1] = cleDeLaSuite === 'il_en_existe_peut_etre_d_autres' ? j.next_cursor : null;
      direLaFenetre(j);
      // Total PLAFONNÉ -> `-1` : le pager partagé passe en « page N » avec des flèches fiables plutôt que
      // de numéroter jusqu'à un dernier numéro qui rendrait les pages suivantes inatteignables.
      if (typeof j.total === 'number') totalDeLaFenetre = j.total_capped ? -1 : j.total;
      // `P10.21-x` — UN TOTAL NON SERVI N'EST PLUS RENDU COMME ZÉRO. Le `0` d'avant faisait de la page une
      // page UNIQUE pour le pager partagé : aucune flèche, alors que la ligne de fenêtre venait de dire
      // qu'un curseur de suite était servi. `null` dit « non compté », et la SUITE part avec la page pour
      // que la flèche la suive.
      return { rows: j.entries || [], total: totalDeLaFenetre, suite: cleDeLaSuite };
    },
  });
}


// `P11.18-s` — CE QUE CETTE VUE EXPORTE POUR L'AUTRE, ET CE QU'ELLE N'EXPORTE PLUS. Le CHOIX DE
// DATES n'est plus ici : il est au point commun (`web/plage_de_dates.js`), avec son lecteur pur, ses refus et
// son écrivain, et il sert LES DEUX VUES QUI POSENT LA BARRE. Le chiffre « quatre » écrit ici comptait
// la famille entière des gestes de plage, modale comprise ; rien ne le suivait. Ce qui part encore
// d'ici est ce qui appartient vraiment à ces deux vues : la CIBLE où leur plage se pose — la valeur partagée — et les deux
// gestes qui la lisent et l'écrivent. `joursPourLeJournal` reste PURE et exportée pour être éprouvée
// sans document ni réseau : c'est la traduction que la route de CETTE vue impose, elle n'appartient
// donc à aucune autre.
// `P10.20-q` : `motDuGenreDeRegistre` et `celluleDeGenre` partent pour être éprouvés sur les littéraux
// LUS dans l'arbre du démon (harnais ESM, témoin 101) — la phrase d'un genre distinct et le jeton qui
// reste cherchable ne se mesurent pas depuis une page chargée.
// `P10.21-c` : `motDeLaSuiteDuJournal` part pour le harnais ESM (témoin 106) — les trois issues ne se
// distinguent qu'en jugeant, face par face, ce que la vue peint sur les trois corps que la route peut servir.
export { loadLedger, CIBLE_DE_PLAGE, joursPourLeJournal, plageActive, poserLaPlage, motDuGenreDeRegistre, celluleDeGenre, motDeLaSuiteDuJournal };

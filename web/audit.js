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
  sel.addEventListener('change', () => { fenetreJours = parseInt(sel.value, 10) || 0; loadLedger(); });
  outils.insertBefore(sel, outils.firstChild);
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
  curseurs = [null];   // toute (re)construction repart de la première page : un curseur d'une autre fenêtre ne veut rien dire
  totalDeLaFenetre = null;   // …et un total d'une autre fenêtre non plus
  plafondDeComptage = null;
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
      let url = '/ledger?limit=' + limit + '&window_days=' + fenetreJours;
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


export { loadLedger };

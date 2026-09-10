// coupe_de_liste.js — LA PHRASE D'UNE LISTE BORNÉE QUI DIT SA COUPE, écrite une fois pour les surfaces ralliées
// par `P11.22-g` (2026-09-10). Le démon sert, à côté d'une liste bornée, l'aveu du fabricant partagé
// (`handlers::liste_bornee`) : `served` (rendues), `window` (la borne), `total`/`total_capped` (comptage borné)
// ou `truncated` (la ligne excédentaire a existé) — nus quand la liste EST le corps, préfixés du nom de la
// liste quand elle vit dans un corps plus grand (`contributions_served`, …). Ce module LIT cet aveu et rend
// une phrase, ou rien : rien quand la borne n'a pas mordu, et rien aussi quand le démon n'a servi AUCUN aveu
// — un compte non publié n'est jamais rendu comme un zéro, et `lectureDeCoupe` distingue les deux cas.
//
// Une seule lecture de « la coupe mord-elle ? » pour toutes ces surfaces : l'écrire à chaque site la
// laisserait diverger, comme les vingt bornes ont divergé avant d'avoir un fabricant.
import { LANG } from './core.js';

const cle = (prefixe, nom) => (prefixe ? prefixe + '_' + nom : nom);
const nombre = v => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const booleen = v => (typeof v === 'boolean' ? v : null);

/// Ce que l'aveu servi PERMET de dire. `connue` = le démon a servi au moins `served` ; `coupee` = null tant
/// que rien ne permet de conclure, sinon le verdict fondé sur `truncated`, `total_capped` ou `total > served`.
export function lectureDeCoupe(d, prefixe) {
  const p = prefixe || '';
  const servies = nombre(d && d[cle(p, 'served')]);
  const fenetre = nombre(d && d[cle(p, 'window')]);
  const total = nombre(d && d[cle(p, 'total')]);
  const totalPlafonne = booleen(d && d[cle(p, 'total_capped')]);
  const tronquee = booleen(d && d[cle(p, 'truncated')]);
  if (servies === null) return { connue: false, coupee: null, servies: null, fenetre: null, total: null, totalPlafonne: null };
  let coupee = null;
  if (tronquee !== null) coupee = tronquee;
  else if (totalPlafonne === true) coupee = true;
  else if (total !== null) coupee = total > servies;
  return { connue: true, coupee, servies, fenetre, total, totalPlafonne };
}

/// La phrase, ou la chaîne vide quand il n'y a rien à dire (pas de coupe) ou rien à savoir (aucun aveu servi).
export function phraseDeCoupe(d, prefixe) {
  const l = lectureDeCoupe(d, prefixe);
  if (!l.connue || l.coupee !== true) return '';
  const fenetre = l.fenetre !== null ? l.fenetre : l.servies;
  if (l.total !== null && l.totalPlafonne !== true && l.total > l.servies) {
    return LANG === 'en'
      ? l.servies + ' served out of ' + l.total + ' — the list is cut'
      : l.servies + ' servies sur ' + l.total + ' — la liste est coupée';
  }
  const auMoins = l.total !== null && l.totalPlafonne === true ? (LANG === 'en' ? ' (at least ' + l.total + ')' : ' (au moins ' + l.total + ')') : '';
  return LANG === 'en'
    ? l.servies + ' served within a window of ' + fenetre + ' — the list is cut, more exist' + auMoins
    : l.servies + ' servies sur une fenêtre de ' + fenetre + ' — la liste est coupée, il en existe davantage' + auMoins;
}

/// La coupe que la CONSOLE fait elle-même en n'affichant qu'une partie de ce qu'elle a reçu : dite aussi.
export function phraseDAffichagePartiel(visibles, recues) {
  const v = nombre(visibles), r = nombre(recues);
  if (v === null || r === null || r <= v) return '';
  return LANG === 'en' ? v + ' shown out of ' + r + ' received' : v + ' affichées sur ' + r + ' reçues';
}

/// L'échantillon d'un tableau de métriques (MTTA/MTTR) : dit quand il a été coupé, avec sa fenêtre.
export function phraseDEchantillonCoupe(m) {
  if (!m || m.sample_truncated !== true) return '';
  const fenetre = nombre(m.sample_window);
  return LANG === 'en'
    ? 'MTTA/MTTR computed on a sample cut at ' + (fenetre !== null ? fenetre : '?') + ' cases — not on the whole window'
    : 'MTTA/MTTR calculés sur un échantillon coupé à ' + (fenetre !== null ? fenetre : '?') + ' dossiers — pas sur la fenêtre entière';
}

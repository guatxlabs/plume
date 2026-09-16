// composer_depuis_lexistant.js — CE QUE LE PRODUIT PORTE DÉJÀ, OFFERT À QUI COMPOSE (`P11.13-a`).
//
// CE QUI A ÉTÉ MESURÉ AVANT D'ÉCRIRE UNE LIGNE, ET CE QUI EN A ÉTÉ RÉFUTÉ (2026-08-23, par lecture du
// code servi, citations à l'appui). Le constat annonçait quatre absences ; deux n'en étaient pas.
//   · RÉFUTÉ — « les modèles enregistrés ne sont pas offerts à qui compose une requête ». La barre de
//     recherche porte un bouton « Modèles » (`index.html`) qui ouvre une palette listant LES DEUX stocks,
//     les modèles livrés ET les requêtes enregistrées, avec charger / modifier / supprimer / copier
//     (`soql_complete.js`, `openTemplatePalette`). C'est le résultat explicite d'une clé antérieure. La
//     seule lecture sous laquelle la phrase tienne : les gabarits n'apparaissent pas dans la complétion
//     AU FIL DE LA FRAPPE, qui n'émet que des jetons de schéma — un autre geste, un autre sujet.
//   · RÉFUTÉ À MOITIÉ — « composer un panneau depuis un modèle ou une requête enregistrée ». Le chemin
//     EXISTE de bout en bout, mais indirect et non annoncé : la palette charge la requête dans la barre
//     de recherche, et la création d'un panneau pré-remplit son champ avec le texte de cette barre. Deux
//     espaces à traverser, et rien ne le dit. Ce qui manquait n'était donc pas le transport : c'était de
//     pouvoir CHOISIR dans l'inventaire, là où l'on compose.
//   · CONFIRMÉ — « composer un panneau depuis une RÈGLE » : rien, nulle part. La requête d'une règle
//     n'apparaît que dans une infobulle du catalogue.
//   · CONFIRMÉ, ET LE MÉCANISME EXISTAIT — la dérivation « requête d'une règle rendue réutilisable » est
//     construite, testée et servie… uniquement sur les ALERTES, donc atteignable seulement depuis une
//     alerte déjà levée. Le démon la rend désormais aussi sur `/api/rules` (`query_reutilisable`).
//
// POURQUOI CE MODULE PLUTÔT QU'UN AJOUT AUX TABLEAUX DE BORD. Le patron « choisir une définition
// réutilisable dans la fenêtre de création d'un panneau » EXISTE DÉJÀ — c'est le sélecteur de panneau de
// bibliothèque. Il ne couvre qu'un stock sur les quatre que le produit porte. Ce module est l'inventaire
// des trois autres, séparé du rendu des tableaux de bord parce qu'il ne connaît rien d'un tableau de
// bord : il liste ce qui porte une requête, et rend le choix.
//
// CE QU'IL NE FAIT PAS, ET POURQUOI. Il ne liste PAS les panneaux de bibliothèque : les référencer n'est
// pas les copier (un panneau de bibliothèque est édité une fois et à jour partout), et le sélecteur qui
// les porte dit cette relation-là. Les mélanger dans une même liste ferait croire à un même geste.
// Il n'écrit rien : il rend un choix, l'appelant compose.
import { api, modal, muted, pagedList } from './core.js';
import { champDeRecherche, filtrerParRecherche, resumeDeRecherche, texteCherchable } from './recherche_de_liste.js';
import { fetchSaved } from './savedqueries.js';

// Combien de lignes par page dans la fenêtre de choix : assez pour parcourir, assez peu pour que la
// fenêtre ne pousse pas le bouton de validation hors de l'écran.
const PAGE_CHOIX = 8;

// LES TROIS STOCKS, ET CE QU'ON LIT DE CHACUN. `charger` rend la liste NORMALISÉE ; une erreur remonte,
// elle n'est pas avalée (cf. `inventaireComposable`).
const STOCKS = [
  {
    cle: 'modele', origine: 'modèle livré',
    charger: async () => ((await api('/soql/templates')).templates || []).map(t => ({
      cle: 'modele:' + t.id, origine: 'modèle livré', titre: t.title || t.id,
      requete: t.soql || '', is_soql: true, viz: 'table', detail: (t.keywords || []).join(' '),
    })),
  },
  {
    cle: 'enregistree', origine: 'ma requête',
    // `fetchSaved` est la lecture DÉJÀ partagée des requêtes enregistrées (elle sert aussi à la palette
    // de la barre de recherche) : rien n'est réécrit ici.
    charger: async () => {
      const l = await fetchSaved();
      if (l === null) throw new Error('lecture refusée');
      return l.map(q => ({
        cle: 'enregistree:' + q.id, origine: 'ma requête', titre: q.name || ('#' + q.id),
        requete: q.soql || '', is_soql: true, viz: 'table', detail: '',
      }));
    },
  },
  {
    cle: 'regle', origine: 'règle de détection',
    // `query_reutilisable` est DÉRIVÉE PAR LE DÉMON (étage scalaire terminal retiré en GXQL, brut intact
    // avec ses marqueurs de fenêtre). La console ne recompose pas la requête d'une règle : elle
    // n'aurait aucun moyen de savoir quel étage réduit la valeur à un nombre.
    // `P10.20-a` — UN STOCK NON LU EST DÉJÀ NOMMÉ PAR CETTE FENÊTRE ; ENCORE FALLAIT-IL QU'IL LE SOIT.
    // `rules_list` (daemon/src/handlers/detection.rs) refuse EN 200 par le constructeur partagé :
    // `{rules: [], error: <cause>}`. `api()` ne jette que sur `!r.ok`, et `(…).rules || []` rendait donc une
    // liste VIDE que `inventaireComposable` prenait pour un stock LU et complet : la fenêtre se lisait
    // « ce déploiement n'a aucune règle réutilisable », et l'aveu « stock NON LU » qui vit dix lignes plus
    // bas ne se déclenchait jamais. Le corps est LIÉ, sa cause LUE, et le refus emprunte le chemin d'échec
    // que ce module a déjà — `charger` jette, l'inventaire nomme le stock absent AVEC la cause servie.
    charger: async () => {
      const rep = await api('/rules');
      if (rep && rep.error) throw new Error(String(rep.error).trim());
      return (rep.rules || [])
        .filter(r => (r.query_reutilisable || '').trim())
        .map(r => ({
          cle: 'regle:' + r.id, origine: 'règle de détection', titre: r.name || ('#' + r.id),
          requete: r.query_reutilisable, is_soql: !!r.is_soql, viz: 'table', detail: r.mitre || '',
        }));
    },
  },
];

// L'INVENTAIRE, ET CE QU'IL AVOUE. Un stock qu'on n'a pas pu lire est NOMMÉ : sans cela, une lecture
// refusée se lirait « ce déploiement n'a aucune règle », ce qui est une autre phrase — et la fenêtre
// paraîtrait complète en ne l'étant pas. Les stocks sont chargés en parallèle ; l'échec de l'un ne prive
// pas des autres.
async function inventaireComposable() {
  const resultats = await Promise.all(STOCKS.map(async s => {
    try { return { stock: s, items: await s.charger() }; }
    catch (e) { return { stock: s, items: null, err: (e && e.message) || String(e) }; }
  }));
  const items = [];
  const absents = [];
  for (const r of resultats) {
    // Le stock absent est nommé AVEC la cause servie : « règle de détection » seul ne dit pas si la lecture
    // a été refusée, rejetée ou jamais partie, et c'est ce que l'exploitant a besoin de savoir pour décider
    // s'il compose quand même. La cause voyage donc à côté de l'origine, jamais fondue dedans.
    if (r.items === null) absents.push({ origine: r.stock.origine, cause: String(r.err || '').trim() });
    else items.push(...r.items);
  }
  return { items, absents };
}

// Le texte cherchable d'une ligne : le domaine reste ici, le module de recherche ne devine aucun champ.
function texteDUnChoix(c) {
  return texteCherchable([c.titre, c.origine, c.detail, c.requete]);
}

// LA FENÊTRE DE CHOIX. Bâtie dans la modale PARTAGÉE du dépôt (fente `body`) plutôt que dans un calque
// de plus : trois calques maison existaient déjà faute de cette fente, et en écrire un quatrième aurait
// été le mécanisme concurrent que ce chantier cherche justement à ne pas produire.
//
// LE CHOIX SE FAIT EN DEUX TEMPS (cliquer une ligne, puis valider) et non d'un clic. Deux raisons : la
// modale partagée résout sur sa validation ou son abandon — un troisième chemin de sortie lui serait
// propre à ce panneau — et le texte de la requête choisie mérite d'être relu avant d'être repris.
// Rend l'élément choisi, ou `null` si la fenêtre est abandonnée.
async function choisirDansLexistant(opts = {}) {
  const { items, absents } = await inventaireComposable();
  const corps = document.createElement('div');
  corps.className = 'compo-choix';
  if (absents.length) {
    // AVEU À DEUX NŒUDS : la phrase, écrite au puits et donc traduisible, puis les stocks et leurs causes
    // SERVIES, composés — `i18nWalk` n'égale qu'un nœud texte ENTIER, et une chaîne « phrase + cause »
    // n'égalerait jamais une clé de lexique.
    const aveu = document.createElement('div'); aveu.className = 'fwarn compo-absents'; aveu.style.cssText = 'font-size:11px;margin:0 0 6px';
    const dit = document.createElement('span');
    dit.textContent = 'Stock NON LU, donc absent de cette liste — ce n\'est pas « il n\'y en a aucun ». Le démon en nomme la cause :';
    aveu.append(dit, ' ' + absents.map(a => a.origine + (a.cause ? ' « ' + a.cause + ' »' : '')).join(' · '));
    corps.appendChild(aveu);
  }
  const champ = document.createElement('input');
  champ.type = 'search'; champ.className = 'compo-recherche';
  champ.placeholder = 'Rechercher un modèle, une requête, une règle…';
  champ.setAttribute('aria-label', 'Rechercher dans ce que le produit porte déjà');
  corps.appendChild(champ);
  const zoneResume = document.createElement('div'); corps.appendChild(zoneResume);
  const liste = document.createElement('div'); liste.className = 'compo-liste'; corps.appendChild(liste);
  if (!items.length) corps.appendChild(muted('aucune définition réutilisable — ni modèle livré, ni requête enregistrée, ni règle de détection'));

  let choisi = null;
  const chercher = champDeRecherche(champ, { auChangement: () => peindre() });

  function ligneDUnChoix(c) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'picon compo-ligne' + (choisi && choisi.cle === c.cle ? ' compo-choisie' : '');
    b.style.cssText = 'display:block;width:100%;text-align:left';
    const t = document.createElement('b'); t.textContent = c.titre;
    const o = document.createElement('span'); o.className = 'badge compo-origine'; o.style.marginLeft = '6px'; o.textContent = c.origine;
    const q = document.createElement('span'); q.className = 'muted compo-requete'; q.style.cssText = 'display:block;font-size:10px';
    q.textContent = c.requete;
    b.append(t, o, q);
    b.title = c.requete;
    b.onclick = () => { choisi = c; peindre(); };
    return b;
  }

  function peindre() {
    const requete = chercher.valeur();
    const filtrees = filtrerParRecherche(items, requete, texteDUnChoix);
    zoneResume.replaceChildren();
    if (requete) {
      zoneResume.appendChild(resumeDeRecherche(filtrees.length, items.length, {
        filtre: document.createTextNode('définition(s) réutilisable(s)'),
        vide: document.createTextNode('aucune définition ne porte « ' + requete +' » — ni dans son nom, ni dans sa requête'),
      }));
    }
    pagedList(liste, { mode: 'client', pageSize: PAGE_CHOIX, rows: filtrees, renderRow: ligneDUnChoix, emptyText: 'aucune définition' });
  }
  peindre();

  const r = await modal({
    title: opts.title || 'Partir de ce qui existe déjà',
    message: opts.message || 'Les modèles livrés, vos requêtes enregistrées et les requêtes de vos règles de détection. La définition choisie est COPIÉE : la modifier ensuite ne touche pas son original.',
    body: corps, okText: 'Utiliser', danger: false,
    validate: () => (choisi ? null : 'Choisissez une définition, ou fermez cette fenêtre.'),
  });
  return r === null ? null : choisi;
}

export { inventaireComposable, choisirDansLexistant, texteDUnChoix };

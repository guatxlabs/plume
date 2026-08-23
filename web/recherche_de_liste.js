// recherche_de_liste.js — LE champ de recherche des listes de la console, partagé.
//
// POURQUOI UN MODULE NEUF PLUTÔT QU'UNE REPRISE. Mesuré le 2026-08-23 par dérivation sur `web/` : la
// console rendait TROIS filtres de liste et aucun n'était reprenable.
//   · le filtre des indicateurs (`#ti-search`) : un écouteur câblé en place, fermé sur une variable de
//     module (`_iocSearch`) et sur le rendu de CE panneau ;
//   · le filtre du glossaire de l'aide : masque des lignes déjà rendues par `hidden` ;
//   · la recherche de la palette de modèles : redessine sa propre liste.
// Trois formes, trois vocabulaires, aucune fabrique — et donc rien à prendre pour un quatrième panneau.
// Ce module est LA forme unique : il ne connaît ni le domaine, ni la liste, ni le rendu ; il rend le
// texte cherchable d'une ligne, le prédicat, et le câblage d'un champ. Les panneaux gardent leur rendu.
//
// CE QU'IL NE FAIT PAS. Il ne trie pas et ne filtre pas à la place des sélecteurs existants : la
// recherche se COMPOSE avec eux (l'appelant trie d'abord, cherche ensuite, ou l'inverse — l'ordre reste
// le sien). Il ne débounce pas : le filtrage est une comparaison de chaînes en mémoire sur des lignes
// DÉJÀ chargées, sans réseau ; un délai n'achèterait qu'une frappe qui traîne.
//
// P11.12-a — le panneau des règles ne se cherchait pas. Un déploiement portant des milliers de règles
// rend la liste inexploitable, et le tri par gravité (qui existait) ne répond pas à « où est la règle
// qui compte les échecs SSH ».

// Un accent n'est pas une différence de sens dans une recherche : « fenetre » doit trouver « fenêtre ».
// NFD sépare la lettre de son signe, la plage U+0300..U+036F retire les signes.
const RE_DIACRITIQUES = /[\u0300-\u036f]/g;
function normaliser(v) {
  return String(v == null ? '' : v).normalize('NFD').replace(RE_DIACRITIQUES, '').toLowerCase();
}

// Les mots d'une recherche. Plusieurs mots = ET (« ssh brute » ne trouve que ce qui porte les deux) :
// c'est le resserrement qu'un analyste attend quand il ajoute un mot, pas un élargissement.
function motsDeLaRecherche(requete) {
  return normaliser(requete).split(/\s+/).filter(Boolean);
}

// Le prédicat, seul, pour un appelant qui a déjà son texte.
function correspondALaRecherche(texte, requete) {
  const mots = motsDeLaRecherche(requete);
  if (!mots.length) return true;
  const n = normaliser(texte);
  return mots.every(m => n.includes(m));
}

// Le filtre. `texteDeLaLigne(ligne)` rend ce qui est cherchable pour CETTE famille de lignes : le
// domaine reste chez l'appelant, ce module ne devine aucun champ. Recherche vide = la liste entière
// (une copie : l'appelant peut trier le résultat sans toucher à l'original).
function filtrerParRecherche(lignes, requete, texteDeLaLigne) {
  const source = Array.isArray(lignes) ? lignes : [];
  const mots = motsDeLaRecherche(requete);
  if (!mots.length) return source.slice();
  return source.filter(l => {
    const n = normaliser(texteDeLaLigne(l));
    return mots.every(m => n.includes(m));
  });
}

// Le texte cherchable d'une ligne : les valeurs utiles, jointes, les vides écartées. L'appelant nomme
// les valeurs ; ce module garantit qu'une valeur absente ne colle pas deux mots l'un à l'autre.
function texteCherchable(valeurs) {
  return (valeurs || []).filter(v => v != null && v !== '').join(' ');
}

// Câblage d'un champ `<input type="search">` DÉJÀ posé dans `index.html` (le champ appartient au
// panneau, pas à ce module : sa place, son libellé et son aide sont ceux de son panneau, et passent
// par le lexique comme tout libellé). Le chrome partagé `.field` est appliqué ici pour qu'aucun champ
// de recherche ne retombe au cadre natif du navigateur (même geste que `P11.4-b` sur `#ti-search`).
// Échap vide le champ ET relance le rendu : sortir d'une recherche ne doit pas demander de sélectionner
// le texte. Rend une poignée : `valeur()` lit la recherche courante, `poser(v)` l'impose depuis
// ailleurs (une autre surface qui ouvre CE panneau sur un critère), `vider()` la retire.
function champDeRecherche(champ, opts = {}) {
  const auChangement = opts.auChangement || (() => {});
  const valeur = () => (champ && champ.value ? String(champ.value).trim() : '');
  if (!champ) return { valeur: () => '', poser: () => {}, vider: () => {} };
  champ.classList.add('field');
  champ.addEventListener('input', () => auChangement(valeur()));
  champ.addEventListener('keydown', e => {
    if (e && e.key === 'Escape' && valeur()) { champ.value = ''; auChangement(''); }
  });
  const poser = v => { champ.value = v == null ? '' : String(v); auChangement(valeur()); };
  return { valeur, poser, vider: () => poser('') };
}

// Ce qu'une liste filtrée DIT d'elle-même. Une liste qui cache des lignes sans le dire ment par
// omission : le compte affiché sur le compte total est la seule façon de savoir qu'on ne regarde plus
// tout. Ce module ne pose que la forme et les nombres.
// LES DEUX PHRASES SONT DES NŒUDS, PAS DES CHAÎNES. Le nom de ce qu'un panneau liste appartient à ce
// panneau, et son libellé doit passer par le lexique de SON module. Reçues en chaînes, elles seraient
// écrites ici sous une clé quelconque, invisible à la garde d'i18n — qui ne lit un littéral que derrière
// un puits qu'elle connaît. Reçues en nœuds, l'appelant les écrit derrière `createTextNode`, la garde
// les voit là où elles sont écrites, et ce module n'a aucun mot de domaine à traduire.
// `vide` doit dire CE QUI EST CHERCHÉ : sans cela une liste sans résultat reste indevinable.
function resumeDeRecherche(affichees, total, textes = {}) {
  const el = document.createElement('div');
  el.className = 'muted recherche-resume';
  if (!affichees) { if (textes.vide) el.appendChild(textes.vide); return el; }
  const compte = document.createElement('b');
  compte.textContent = affichees + ' / ' + total;
  el.append(compte, document.createTextNode(' '));
  if (textes.filtre) el.appendChild(textes.filtre);
  return el;
}

export { normaliser, motsDeLaRecherche, correspondALaRecherche, filtrerParRecherche, texteCherchable, champDeRecherche, resumeDeRecherche };

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

// ==================================================================================================
// `P11.18-z` — LA RECHERCHE SURVIT AU RENDU QUI DÉTRUIT SON CHAMP, ET LA MÉMOIRE EST PAR IDENTITÉ
// --------------------------------------------------------------------------------------------------
// LE DÉFAUT. Le champ appartient à la LISTE : un rechargement de vue ne redessine pas dans le même hôte,
// il vide son conteneur et FABRIQUE un élément neuf. Au moment de reconstruire, le champ précédent
// n'existe plus — donc relire la valeur DANS le champ ne peut pas marcher, et l'aurait fait pour les
// listes dont l'hôte survit et pas pour les autres. La valeur doit donc survivre à la DESTRUCTION de
// l'hôte : elle est retenue ici, sous l'IDENTITÉ de la liste, et non dans un nœud du document.
//
// SANS IDENTITÉ, AUCUNE MÉMOIRE — ET C'EST LE DÉFAUT SÛR. `souvenirDeRecherche('')` rend `null` : la
// liste se comporte exactement comme avant, sans mémoire, jamais à moitié. Aucune identité n'est
// devinée depuis la position d'un hôte ni depuis un libellé : deux listes voisines échangeraient leur
// recherche le jour où une section conditionnelle paraît ou disparaît, et une recherche appliquée à la
// mauvaise liste est pire que pas de mémoire du tout.
//
// EN MÉMOIRE, PAS SUR LE DISQUE, ET C'EST MESURÉ COMME UN CHOIX. Une recherche d'exploitant porte ce
// qu'il cherche — un nom de machine, une adresse, un compte. L'écrire dans un magasin persistant la
// déposerait sur le poste bien après la session ; une table de module la tient aussi longtemps que la
// page vit, ce qui est exactement la portée demandée (un rechargement de VUE), et pas une seconde de
// plus. CE QUE CETTE MÉMOIRE NE TIENT PAS, écrit plutôt que tu : elle ne survit ni au rechargement de la
// PAGE, ni à un autre onglet, ni à un autre navigateur.
//
// CE QU'ELLE RETIENT EN PLUS DE LA REQUÊTE : le nombre de lignes que cette recherche MASQUAIT au dernier
// geste de l'exploitant sur elle. C'est la seule référence qui permette, après coup et sur les NOMBRES
// seuls, de dire qu'une liste en cache maintenant davantage qu'à ce moment-là — sans rien demander à
// l'appelant, donc sans qu'aucune vue puisse retomber du mauvais côté.
// ==================================================================================================
const SOUVENIRS_DE_RECHERCHE = new Map();

function souvenirDeRecherche(identite) {
  const cle = String(identite == null ? '' : identite).trim();
  if (!cle) return null;
  return {
    lire: () => SOUVENIRS_DE_RECHERCHE.get(cle) || null,
    // Une recherche VIDE n'est pas un souvenir : elle est l'absence de recherche, et la retenir ferait
    // renaître une entrée que l'exploitant vient d'effacer.
    noter: (requete, masquees) => {
      const q = String(requete == null ? '' : requete);
      if (!q) { SOUVENIRS_DE_RECHERCHE.delete(cle); return; }
      SOUVENIRS_DE_RECHERCHE.set(cle, { requete: q, masquees: Math.max(0, Number(masquees) || 0) });
    },
  };
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

export { normaliser, motsDeLaRecherche, correspondALaRecherche, filtrerParRecherche, texteCherchable, champDeRecherche, resumeDeRecherche, souvenirDeRecherche };

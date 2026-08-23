// copie_et_selection.js — LE CONTRAT DE LA CONSOLE AVEC LA SÉLECTION ET LE PRESSE-PAPIER, partagé.
//
// CE QUI ÉTAIT CASSÉ (`P11.4-h`). Un exploitant rapporte que sélectionner puis copier un fragment rend la
// LIGNE ENTIÈRE, et qu'une partie de l'interface ne se copie pas du tout. MESURE du 2026-08-23, par
// dérivation sur `web/` :
//   · UN CLIC QUI AVALE LA SÉLECTION. Chaque ligne du tableau de résultats porte `tr.onclick` (drilldown,
//     ou dépli du détail) et chaque titre d'alerte porte `.alertdrill`. Un glisser-sélectionner se termine
//     par un `mouseup` DANS la ligne : le clic part, la vue est redessinée ou remplacée, et la sélection
//     disparaît avec elle. AUCUN des deux gestionnaires ne regardait s'il y avait une sélection —
//     `getSelection` n'était appelé nulle part dans `web/` (0 occurrence mesurée).
//   · UNE SÉLECTION QUI S'ÉTEND À TOUT. `user-select:all` à trois endroits (la boîte de secret `.secretbox`,
//     l'URL de poussée et la clé de livraison d'un connecteur) : cliquer dedans sélectionne l'ÉLÉMENT
//     ENTIER, jamais le fragment visé. C'est délibéré pour un secret d'un seul tenant, et c'est
//     exactement le défaut décrit pour tout le reste.
//   · CE QUI NE SE COPIE PAS. `user-select:none` à quatre endroits : la colonne de numéros de ligne et
//     l'en-tête triable d'un tableau, les graphiques, l'en-tête replié de la fraîcheur. Les trois derniers
//     portent un geste (tri, glisser, dépli) que la sélection gênerait ; le numéro de ligne est du
//     mobilier. Aucun n'est un défaut EN SOI — mais aucune de ces surfaces n'offrait d'autre voie.
//   · AUCUN GESTE DE COPIE PARTAGÉ. `navigator.clipboard` était appelé à DEUX endroits, écrits deux fois
//     (le jeton d'agent et le lien d'instantané), avec deux retours d'écran différents. Les valeurs qu'un
//     exploitant transporte — un identifiant, une adresse, une empreinte, un chemin de document — n'en
//     avaient aucun.
//
// CE QUE CE MODULE POSE. Un clic qui se retire devant une sélection, et UN geste de copie. Il ne connaît
// aucun domaine : l'appelant lui donne l'élément et la valeur. Il ne change RIEN aux `user-select`
// existants — un secret d'un seul tenant a raison de se sélectionner d'un bloc ; ce qui manquait était
// une issue explicite là où il n'y en avait pas.
import { ic, toast } from './core.js';

// LA SÉLECTION EN COURS TOUCHE-T-ELLE `hote` ? Trois précautions, chacune pour un faux positif observé :
//   · `isCollapsed` — un simple clic laisse une sélection VIDE au point cliqué ; sans ce test, plus aucun
//     clic ne passerait, ce qui remplacerait un défaut par une interface morte ;
//   · le texte non blanc — une sélection réduite à une espace ne vaut pas qu'on annule un geste ;
//   · l'ANCRAGE dans `hote` — une sélection faite ailleurs dans la page ne doit pas geler CE clic-là.
// Le tout sous `try` : `getSelection` n'existe pas dans tous les contextes de rendu (harnais, worker), et
// une erreur ici doit rendre le clic à son comportement d'origine, jamais casser la page.
function selectionEnCours(hote) {
  try {
    const sel = typeof window !== 'undefined' && window.getSelection ? window.getSelection() : null;
    if (!sel || sel.isCollapsed || !String(sel).trim()) return false;
    if (!hote || typeof hote.contains !== 'function') return false;
    const n = sel.anchorNode;
    const el = n && n.nodeType === 3 ? n.parentNode : n;
    return !!el && (el === hote || hote.contains(el));
  } catch (e) { return false; }
}

// UN CLIC QUI RESPECTE LA SÉLECTION. Rend `el`, pour l'enchaînement. `handler` reçoit l'événement.
// POURQUOI PAS `mousedown`/`mouseup` : le geste à protéger est le GLISSER, dont seule la fin coïncide avec
// le clic ; c'est donc au clic de se retirer, et lui seul — le clavier (`Enter`) n'est pas concerné.
function clicQuiRespecteLaSelection(el, handler) {
  if (!el) return el;
  el.onclick = (e) => { if (selectionEnCours(el)) return undefined; return handler(e); };
  return el;
}

// LE GESTE DE COPIE, ÉCRIT UNE FOIS. `valeur` peut être une fonction : une valeur qui n'existe qu'au moment
// du clic (un extrait recomposé) n'a pas à être figée à la construction. `opts.libelle` remplace le mot du
// bouton, `opts.titre` sa phrase de survol, `opts.avecMot` rend le mot à côté de l'icône (un bouton nu en
// icône suffit dans une ligne dense, pas dans une modale). Le retour d'écran est le MÊME partout : le
// bouton dit « Copié » puis reprend son mot ; une infobulle le double, parce qu'un bouton en icône seule
// ne porte pas assez de place pour être lu.
// Le repli `execCommand` reste : `navigator.clipboard` exige un contexte sécurisé, et la console se sert
// aussi en HTTP sur un réseau d'administration.
const DUREE_ACCUSE_MS = 1600;
function boutonDeCopie(valeur, opts = {}) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'copybtn';
  const mot = opts.libelle || 'Copier';
  const peindre = (texte) => { b.innerHTML = ic('copy'); if (opts.avecMot !== false) b.appendChild(document.createTextNode(' ' + texte)); };
  peindre(mot);
  b.title = opts.titre || 'Copier cette valeur';
  b.setAttribute('aria-label', b.title);
  b.onclick = async (e) => {
    if (e && e.stopPropagation) e.stopPropagation();
    const v = typeof valeur === 'function' ? String(valeur() ?? '') : String(valeur ?? '');
    let pose = false;
    try { await navigator.clipboard.writeText(v); pose = true; } catch (err) {
      try {
        const zone = document.createElement('textarea');
        zone.value = v; zone.setAttribute('readonly', 'true'); zone.style.position = 'fixed'; zone.style.left = '-9999px';
        document.body.appendChild(zone); zone.select(); pose = document.execCommand('copy'); zone.remove();
      } catch (e2) { pose = false; }
    }
    // ÉCHEC DIT, JAMAIS TU : un bouton qui reprend son mot sans rien avoir copié fait recopier à la main
    // une valeur qu'on croit dans le presse-papier.
    if (!pose) { toast('Copie refusée par le navigateur — sélectionnez la valeur et copiez-la à la main', 'bad'); return; }
    peindre('Copié'); toast('Copié', 'ok');
    setTimeout(() => peindre(mot), DUREE_ACCUSE_MS);
  };
  return b;
}

// UNE VALEUR QU'ON TRANSPORTE : le texte, lisible et sélectionnable, ET son geste de copie. C'est la forme
// que prend un identifiant, une adresse, une empreinte ou un chemin de document partout où la console en
// affiche un. Rend un fragment (le texte et le bouton côte à côte) : l'appelant décide de son entourage.
function valeurTransportee(valeur, opts = {}) {
  const frag = document.createDocumentFragment();
  const code = document.createElement('code');
  code.className = 'copyval';
  code.textContent = String(valeur ?? '');
  frag.append(code, boutonDeCopie(valeur, { avecMot: false, titre: opts.titre || 'Copier cette valeur', libelle: opts.libelle }));
  return frag;
}

export { selectionEnCours, clicQuiRespecteLaSelection, boutonDeCopie, valeurTransportee };

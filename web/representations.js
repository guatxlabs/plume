// `P11.20-d` — LA LISTE UNIQUE DES REPRÉSENTATIONS d'un résultat, et le geste qui la pose dans un choix.
// Mesuré le 2026-08-25 (`P11.18-a`) : la barre de recherche n'offrait pas les mêmes représentations que les
// panneaux — quatre contre neuf — parce que la liste était écrite QUATRE fois (deux tableaux et une chaîne
// HTML dans dashboards.js, un <select> statique dans index.html) et qu'un ajout n'atteignait jamais l'éditeur.
// Une liste, un ordre, une icône par représentation ; l'éditeur, le sélecteur d'un panneau et les deux
// formulaires de panneau se posent depuis elle. Module feuille : il n'importe rien.
export const REPRESENTATIONS = [
  { value: 'table', label: 'Table' },
  { value: 'bar', label: 'Barres' },
  { value: 'line', label: 'Courbe' },
  { value: 'stat', label: 'Stat' },
  { value: 'gauge', label: 'Jauge' },
  { value: 'pie', label: 'Camembert' },
  { value: 'donut', label: 'Donut' },
  { value: 'heatmap', label: 'Heatmap' },
  { value: 'histogram', label: 'Histogramme' },
];

// L'icône de chaque représentation (nom d'icône de `ic()` dans core.js) : la même dans le sélecteur d'un
// panneau, quelle que soit la surface qui le dessine.
export const ICONE_DE_REPRESENTATION = { table: 'table', bar: 'bars', line: 'activity', stat: 'hash', gauge: 'gauge', pie: 'pie', donut: 'pie', heatmap: 'grid', histogram: 'histogram' };

// La représentation par défaut d'un résultat : celle qui ne perd aucune colonne.
export const REPRESENTATION_PAR_DEFAUT = 'table';

// Pose les neuf représentations dans un <select> (vidé d'abord) et garde la valeur voulue si elle existe
// encore ; une valeur inconnue retombe sur la table, jamais sur une option absente.
export function poserLesRepresentations(select, voulue) {
  if (!select) return;
  const cible = voulue || select.value || REPRESENTATION_PAR_DEFAUT;
  select.replaceChildren(...REPRESENTATIONS.map((r) => {
    const o = document.createElement('option');
    o.value = r.value;
    o.textContent = r.label;
    return o;
  }));
  select.value = REPRESENTATIONS.some((r) => r.value === cible) ? cible : REPRESENTATION_PAR_DEFAUT;
}

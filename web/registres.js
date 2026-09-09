// registres.js — LES REGISTRES QUE PLUSIEURS MODULES REMPLISSENT AU CHARGEMENT, dans un module FEUILLE.
//
// `P11.21-f` (2026-09-09). Trois portes du graphe de modules JETAIENT quand on entrait par elles
// (`attack.js`, `navigation.js`, `threatintel.js`) : un cycle d'imports faisait évaluer `app.js` ou
// `detection_admin.js` AVANT le corps du module d'entrée, et leurs appels de premier niveau
// (`poserLesPortesDeTechnique`, `poserUneCharge`, `initThreatIntel`) touchaient une constante de ce module
// encore en ZONE MORTE TEMPORELLE — `PORTES`, `CHARGES_DE_LA_CONSOLE`, `_iocSearch`. Différer ces appels a
// été essayé et refusé par le harnais (témoin 53c) ; ce qui les guérit est STRUCTUREL : la valeur écrite
// au chargement vit ici, dans un module qui n'importe RIEN — il est donc évalué en premier, quelle que
// soit la porte, et n'est jamais en zone morte. Les fonctions, elles, sont des déclarations hissées :
// elles ne posaient pas le problème.
//
// Ce module ne DÉCIDE rien : il porte des cases. Qui les remplit et qui les lit reste écrit là où le
// geste a un sens (`attack.js`, `navigation.js`, `threatintel.js`).

/// Les portes qu'une technique ATT&CK ouvre vers le panneau des règles (`attack.js` lit, `detection_admin.js` pose).
export const PORTES_DE_TECHNIQUE = { regles: null, creer: null };

/// Les peintres attachés aux charges DÉCLARÉES `pose: true` (`navigation.js` lit, `app.js` pose). La liste
/// des charges reste dans `navigation.js` ; ici ne vit que l'attache, cible -> fonction.
export const CHARGES_POSEES = new Map();

/// Le filtre de recherche courant du magasin d'indicateurs (`threatintel.js` seul, lu par son rendu).
export const RECHERCHE_IOC = { valeur: '' };

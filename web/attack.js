// attack.js — matrice de couverture MITRE ATT&CK (espace Détection & Réponse, onglet « ATT&CK »).
// ADDITIF, comportement-préservant. LECTURE seule, viewer+ (donnée de posture, pas un secret).
//
// P11.6-b — UNE TECHNIQUE EST UNE PORTE, PAS UNE CASE DE TABLEAU. La matrice disait la couverture et
// laissait l'analyste repartir de zéro dans un autre panneau. MESURÉ le 2026-08-23 sur les routes servies
// et sur cette surface : la sortie « alertes » EXISTAIT DÉJÀ (le clic posait la facette de la technique
// sur la file d'alertes, `setAlertMitreFilter`, cf. `P11.1-b`), et de là le lien exact vers l'Explore est
// celui que le démon sert AVEC chaque alerte (`search_link`, `P11.1-a`). Ce module ne fabrique donc AUCUNE
// requête : la sortie « détections » reste ce même appel, inchangé. Ce qui manquait, ce sont les deux
// autres sorties — les RÈGLES qui couvrent la technique, et le geste qui la couvrirait quand rien ne la
// couvre. `/api/coverage/attack` ne sert que des COMPTES par technique (aucun identifiant de règle) : la
// porte des règles n'invente pas une jointure côté console, elle ouvre le panneau des règles SUR la
// technique, par la recherche partagée (`P11.12-a`) — l'identifiant d'une cellule est la technique PARENTE,
// et l'inclusion de chaîne y retrouve aussi les règles taguées par une sous-technique.
// Endpoint (construit par le daemon — item concurrent) :
//   GET /api/coverage/attack -> { tactics:[{ tactic, rule_count, covered,
//                                            techniques:[{ tid, name|null, rule_count, alert_count, covered }] }],
//                                 totals }
// Rendu : tactiques en COLONNES, techniques en CELLULES colorées par couverture (couvert = échelle verte
// selon rule/alert_count ; non couvert = grisé -> les ANGLES MORTS ressortent). Clic technique -> ses alertes.
// DÉGRADATION : si l'endpoint 404 (daemon non déployé), message « couverture indisponible » (pas d'erreur dure).
// SÉCU UI : tout en textContent/attributs (anti-XSS). Aucune mutation (aucun apiSend).
import { $, api, muted, socIsAdmin, socRole, mitreName, closeModals } from './core.js';
import { setAlertMitreFilter } from './app.js';
import { openSigmaImport } from './sigmaimport.js';

// P11.6-a — LE NOM D'UNE TECHNIQUE EST DÉRIVÉ, JAMAIS LAISSÉ VIDE. MESURÉ le 2026-08-22 : le démon
// n'émettait aucun `name` et cette matrice rendait `t.name || ''` -> TOUTES les cellules (183 techniques
// du catalogue) n'avaient qu'un numéro. Ordre de résolution : le nom servi par le démon (`attack_names`,
// sous-technique résolue par son parent côté serveur) ; sinon la table locale de `core.js` (qui replie
// déjà `Txxxx.yyy` sur `Txxxx`) ; sinon le MOT « nom inconnu » — un identifiant hors catalogue (retiré,
// personnalisé, mal saisi) se DIT, il ne se tait pas. `null` = inconnu ; jamais une chaîne vide.
const NOM_INCONNU = 'nom inconnu';
function techniqueDisplayName(t) {
  const servi = t && typeof t.name === 'string' ? t.name.trim() : '';
  if (servi) return servi;
  const local = mitreName((t && t.tid) || '');
  return local || null;
}

// Intensité de couverture d'une technique : max(rule_count, alert_count). Sert l'échelle de couleur.
function techWeight(t) { return Math.max(Number(t && t.rule_count) || 0, Number(t && t.alert_count) || 0); }

// Teinte d'une cellule couverte : color-mix de --ok, d'autant plus soutenu que la couverture est dense.
// `w` = poids de la technique, `max` = poids max observé -> pourcentage 16..58 %.
// PLAFOND 58 % (peaufinage lisibilité) : au-delà le vert sature et le texte (--fg) décroche du contraste
// dans les DEUX thèmes (sombre : le vert s'éclaircit vers le fg clair ; clair : le vert fonce vers le fg
// sombre). Le dégradé de densité reste lisible ; la légende ci-dessous reflète les mêmes bornes.
function coveredBg(w, max) {
  const t = max > 0 ? Math.min(1, w / max) : 0;
  const pct = Math.round(16 + t * 42);
  return 'color-mix(in srgb, var(--ok) ' + pct + '%, transparent)';
}

// Une cellule = une technique. Couverte -> fond vert (échelle) ; non couverte -> classe .uncovered (grisé).
function techniqueCell(t, max) {
  const tid = (t && t.tid) || '?';
  const covered = !!(t && t.covered);
  const cell = document.createElement('button');
  cell.type = 'button';
  cell.className = 'attack-cell' + (covered ? '' : ' uncovered');
  if (covered) cell.style.background = coveredBg(techWeight(t), max);
  const rc = Number(t && t.rule_count) || 0;
  const ac = Number(t && t.alert_count) || 0;
  const idEl = document.createElement('span'); idEl.className = 'attack-tid'; idEl.textContent = tid;
  const cnt = document.createElement('span'); cnt.className = 'attack-cnt' + (covered ? '' : ' none');
  cnt.textContent = covered ? (rc + 'r/' + ac + 'a') : 'aucune règle';
  const nom = techniqueDisplayName(t);
  const nameEl = document.createElement('span'); nameEl.className = 'attack-tname' + (nom ? '' : ' attack-tname-inconnu');
  nameEl.textContent = nom || NOM_INCONNU;
  cell.append(cnt, idEl, nameEl);
  // angle mort : état « aucune règle » explicite + indice pour combler (import Sigma). Le clic OUVRE LA
  // PORTE de la technique (`P11.6-b`) : la sortie vers ses alertes y est le même appel qu'avant, à côté de
  // celles qui manquaient. Le raccourci d'import en masse reste aussi sur la légende (admin).
  cell.title = tid + ' — ' + (nom || (NOM_INCONNU + " : identifiant hors du catalogue ATT&CK connu de la console (technique retirée, personnalisée ou mal saisie)"))
    + '\n' + (covered ? (rc + ' règle(s) · ' + ac + ' alerte(s)') : 'ANGLE MORT — aucune règle ne couvre cette technique. Importez un ruleset Sigma pour la couvrir (bouton « Importer un ruleset Sigma »).')
    + '\n' + 'Clic : ses règles, ses alertes, et le geste qui la couvrirait';
  cell.onclick = () => ouvrirLaPorteDeLaTechnique(t);
  return cell;
}

// --- P11.6-b : LA PORTE D'UNE TECHNIQUE ------------------------------------------------------------
// Les deux sorties qui quittent CE panneau sont posées par le panneau des règles lui-même (il seul sait
// ouvrir son formulaire et sa recherche). Elles arrivent ici par injection plutôt que par un import :
// `detection_admin.js` importe déjà ce module, l'importer en retour ferait un cycle dont l'un des deux
// bouts s'évaluerait à moitié.
const PORTES = { regles: null, creer: null };
function poserLesPortesDeTechnique(p) { PORTES.regles = (p && p.regles) || null; PORTES.creer = (p && p.creer) || null; }

// Un bouton de sortie. Une sortie impraticable est RENDUE, inerte, et son `title` DIT POURQUOI : une sortie
// absente ne se distingue pas d'une sortie oubliée. Le motif n'est pas collé au bout d'une phrase — chaque
// cas porte sa phrase ENTIÈRE, parce qu'un libellé composé à l'exécution n'a plus d'entrée exacte au
// lexique et ne se traduit donc jamais. `label:` et `title:` sont le vocabulaire d'option des fabriques de
// bouton de la console (`rowButton`), et les puits que la garde du lexique sait lire.
function sortieDePorte(o) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'btn' + (o.principal && !o.inerte ? ' btn-primary' : '');
  b.textContent = o.label;
  b.title = o.title;
  if (o.inerte) b.disabled = true; else b.onclick = o.onClick;
  return b;
}

// Le contenu de la porte, en un élément — construit sans toucher au document, donc jugeable tel quel.
// `fermer` referme l'enveloppe ; il vaut une fonction vide quand la porte est rendue hors overlay.
function porteDeLaTechnique(t, fermer = () => {}) {
  const tid = (t && t.tid) || '?';
  const nom = techniqueDisplayName(t);
  const couverte = !!(t && t.covered);
  const rc = Number(t && t.rule_count) || 0;
  const ac = Number(t && t.alert_count) || 0;
  const box = document.createElement('div');
  box.className = 'attack-porte';
  const h = document.createElement('h3');
  h.textContent = tid + ' — ' + (nom || NOM_INCONNU);
  const etat = document.createElement('p');
  etat.className = 'modal-msg';
  etat.textContent = couverte
    ? rc + ' règle(s) la couvrent · ' + ac + ' alerte(s) sur la fenêtre de la matrice.'
    : "ANGLE MORT : aucune règle activée ne couvre cette technique. Rien ne la détectera tant qu'aucune ne la porte.";
  const sorties = document.createElement('div');
  sorties.className = 'attack-porte-sorties';

  // 1. LES RÈGLES QUI LA COUVRENT — ouvre le panneau des règles sur cette technique (recherche partagée).
  sorties.appendChild(sortieDePorte({
    label: 'Voir les règles qui la couvrent',
    title: !PORTES.regles ? "Le panneau des règles n'est pas chargé."
      : couverte ? "Ouvre le panneau des règles, la recherche posée sur cette technique (elle y retrouve aussi les règles taguées par une sous-technique)."
      : "Aucune règle ne couvre cette technique : il n'y a rien à ouvrir. C'est la sortie de création qui s'applique.",
    inerte: !PORTES.regles || !couverte,
    principal: couverte,
    onClick: () => { fermer(); if (PORTES.regles) PORTES.regles(tid); },
  }));
  // 2. LES DÉTECTIONS QU'ELLE A NOURRIES — le pivot qui existait déjà, inchangé.
  sorties.appendChild(sortieDePorte({
    label: 'Voir les détections de cette technique',
    title: ac ? "Pose la facette de cette technique sur la file d'alertes ; de là, chaque alerte ouvre la recherche sur ce que sa règle a compté."
      : "Aucune alerte ne porte cette technique sur la fenêtre de la matrice.",
    inerte: !ac,
    onClick: () => { fermer(); setAlertMitreFilter(tid); },
  }));
  // 3. LE GESTE QUI LA COUVRIRAIT — formulaire de règle, technique pré-remplie.
  const peutEcrire = socRole() === 'admin' || socRole() === 'editor';
  sorties.appendChild(sortieDePorte({
    label: couverte ? 'Ajouter une règle sur cette technique' : 'Créer la règle qui la couvrira',
    title: !PORTES.creer ? "Le panneau des règles n'est pas chargé."
      : peutEcrire ? "Ouvre le formulaire de règle avec cette technique déjà renseignée."
      : "Écrire une règle demande le rôle éditeur ; ce compte est en lecture seule.",
    inerte: !PORTES.creer || !peutEcrire,
    principal: !couverte,
    onClick: () => { fermer(); if (PORTES.creer) PORTES.creer(tid); },
  }));
  // 4. COMBLER EN MASSE — l'affordance de la légende, à portée de la technique regardée (admin).
  if (!couverte && socIsAdmin()) {
    sorties.appendChild(sortieDePorte({
      label: 'Importer un ruleset Sigma',
      title: 'Combler les angles morts en masse : importer une bibliothèque de détection Sigma.',
      onClick: () => { fermer(); openSigmaImport(); },
    }));
  }
  sorties.appendChild(sortieDePorte({ label: 'Fermer', title: 'Refermer sans quitter la matrice.', onClick: () => fermer() }));
  box.append(h, etat, sorties);
  return box;
}

// L'enveloppe : même chrome de modale que le reste de la console (`.modal-ov` / `.modal`), et les trois
// fermetures que les autres modales offrent déjà — le bouton, le fond, Échap (cf. `help.js`,
// `sigmaimport.js`). Le harnais juge la fermeture par le BOUTON : son document factice n'appelle aucun
// écouteur, donc ni le fond ni Échap n'y sont observables.
function ouvrirLaPorteDeLaTechnique(t) {
  closeModals();
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal';
  const surTouche = e => { if (e.key === 'Escape') fermer(); };
  const fermer = () => { document.removeEventListener('keydown', surTouche); ov.remove(); };
  box.appendChild(porteDeLaTechnique(t, fermer));
  ov.appendChild(box);
  document.body.appendChild(ov);
  ov.onclick = e => { if (e.target === ov) fermer(); };
  document.addEventListener('keydown', surTouche);
}

// Une colonne = une tactique + ses techniques (couvertes triées en tête, angles morts ensuite).
function tacticColumn(tac, max) {
  const col = document.createElement('div'); col.className = 'attack-col';
  const techs = Array.isArray(tac && tac.techniques) ? tac.techniques.slice() : [];
  const covered = techs.filter(t => t && t.covered).length;
  const h = document.createElement('div'); h.className = 'attack-col-h';
  h.textContent = (tac && tac.tactic) || '(tactique ?)';
  const sub = document.createElement('span'); sub.className = 'attack-col-sub';
  sub.textContent = covered + ' / ' + techs.length + ' couverte(s)';
  h.appendChild(sub); col.appendChild(h);
  // couvertes d'abord (poids décroissant), puis angles morts -> les cellules vertes remontent.
  techs.sort((a, b) => (Number(!!(b && b.covered)) - Number(!!(a && a.covered))) || (techWeight(b) - techWeight(a)));
  techs.forEach(t => col.appendChild(techniqueCell(t, max)));
  return col;
}

// Légende (échelle de couverture) + synthèse (couverture globale, angles morts).
function renderLegend(tactics) {
  const leg = $('#attack-legend'); if (!leg) return;
  leg.replaceChildren();
  leg.className = 'attack-legend';
  let tech = 0, cov = 0;
  tactics.forEach(tac => { (tac.techniques || []).forEach(t => { tech++; if (t && t.covered) cov++; }); });
  const mk = (bg, label, cls) => {
    const s = document.createElement('span');
    const sw = document.createElement('span'); sw.className = 'swatch' + (cls ? ' ' + cls : ''); if (bg) sw.style.background = bg;
    s.append(sw, document.createTextNode(label)); return s;
  };
  leg.append(
    mk('color-mix(in srgb, var(--ok) 22%, transparent)', 'couverte (peu de règles)'),
    mk('color-mix(in srgb, var(--ok) 56%, transparent)', 'couverte (dense)'),
    mk('color-mix(in srgb, var(--mut) 12%, transparent)', 'angle mort (aucune détection)'),
  );
  const summary = document.createElement('span');
  summary.textContent = 'Couverture : ' + cov + ' / ' + tech + ' technique(s) · ' + (tech - cov) + ' angle(s) mort(s)';
  leg.appendChild(summary);
  // AFFORDANCE « fermer les angles morts » : raccourci vers l'import Sigma en masse. Admin only (la modale
  // re-garde de toute façon, serveur = vraie garde). N'apparaît que s'il RESTE des angles morts à combler.
  if ((tech - cov) > 0 && socIsAdmin()) {
    const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'attack-fill'; btn.textContent = 'Importer un ruleset Sigma →';
    btn.title = 'Combler les angles morts : importer une bibliothèque de détection Sigma';
    btn.onclick = openSigmaImport;
    leg.appendChild(btn);
  }
}

async function loadAttackMatrix() {
  const host = $('#attack-body'); if (!host) return;
  const leg = $('#attack-legend'); if (leg) leg.replaceChildren();
  host.replaceChildren(muted('chargement…'));
  let d;
  try { d = await api('/coverage/attack'); }
  catch (e) {
    // dégrade proprement : 404 (daemon pas encore déployé) -> indisponible ; autre -> message d'erreur.
    const msg = (e && e.message) || String(e);
    host.replaceChildren(muted(/(^|\s)404(\s|$)/.test(msg) ? 'couverture ATT&CK indisponible (endpoint non déployé).' : 'couverture indisponible : ' + msg));
    return;
  }
  const tactics = (d && Array.isArray(d.tactics)) ? d.tactics : [];
  if (!tactics.length) { host.replaceChildren(muted('aucune tactique dans la matrice de couverture.')); return; }
  // poids max sur TOUTES les techniques -> échelle de couleur commune (comparaison inter-tactiques honnête).
  let max = 0;
  tactics.forEach(tac => (tac.techniques || []).forEach(t => { const w = techWeight(t); if (w > max) max = w; }));
  renderLegend(tactics);
  const matrix = document.createElement('div'); matrix.className = 'attack-matrix';
  tactics.forEach(tac => matrix.appendChild(tacticColumn(tac, max)));
  host.replaceChildren(matrix);
}

export { loadAttackMatrix, techniqueCell, techniqueDisplayName, porteDeLaTechnique, poserLesPortesDeTechnique, NOM_INCONNU };

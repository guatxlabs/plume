// attack.js — matrice de couverture MITRE ATT&CK (espace Détection & Réponse, onglet « ATT&CK »).
// ADDITIF, comportement-préservant. LECTURE seule, viewer+ (donnée de posture, pas un secret).
// Endpoint (construit par le daemon — item concurrent) :
//   GET /api/coverage/attack -> { tactics:[{ tactic, rule_count, covered,
//                                            techniques:[{ tid, name?, rule_count, alert_count, covered }] }],
//                                 totals }
// Rendu : tactiques en COLONNES, techniques en CELLULES colorées par couverture (couvert = échelle verte
// selon rule/alert_count ; non couvert = grisé -> les ANGLES MORTS ressortent). Clic technique -> ses alertes.
// DÉGRADATION : si l'endpoint 404 (daemon non déployé), message « couverture indisponible » (pas d'erreur dure).
// SÉCU UI : tout en textContent/attributs (anti-XSS). Aucune mutation (aucun apiSend).
import { $, api, muted, socIsAdmin } from './core.js';
import { setAlertMitreFilter } from './app.js';
import { openSigmaImport } from './sigmaimport.js';

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
  const nameEl = document.createElement('span'); nameEl.className = 'attack-tname'; nameEl.textContent = (t && t.name) || '';
  cell.append(cnt, idEl, nameEl);
  // angle mort : état « aucune règle » explicite + indice pour combler (import Sigma). Comportement du clic
  // INCHANGÉ (voir les alertes de la technique) ; le raccourci d'import est le bouton de la légende (admin).
  cell.title = tid + ((t && t.name) ? ' — ' + t.name : '')
    + '\n' + (covered ? (rc + ' règle(s) · ' + ac + ' alerte(s)') : 'ANGLE MORT — aucune règle ne couvre cette technique. Importez un ruleset Sigma pour la couvrir (bouton « Importer un ruleset Sigma »).')
    + '\nClic : voir les alertes ' + tid;
  cell.onclick = () => setAlertMitreFilter(tid);
  return cell;
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

export { loadAttackMatrix };

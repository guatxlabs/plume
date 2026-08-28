// Dashboards (P3) : tuiles, grilles de panneaux (chargement paresseux, rendu, export), instantané partageable (#54),
// diaporama (#54), vues (ensembles de dashboards) et favoris (#62). Extrait d'`app.js` par déplacement pur ; le
// câblage des boutons et les deux chargements initiaux sont exposés par `initDashboards()`, appelé par `app.js`
// au point où ce bloc vivait (un module s'exécute à l'import, avant l'enveloppe `fetch` d'`app.js`). Les seams
// (`viz.js`, `multitenant.js`) continuent de lire `loadDashboard` / `refreshPanels` via le ré-export d'`app.js`.
// `renderDashboard` est exporté pour le harnais. N'importe pas `app.js`.
import { $, ic, flashStopped, stopBtn, toast, modal, confirmModal, confirmWithConsequence, toCSV, downloadText, tsSlug, exportPDF, miniMenu, api, apiSend, transientGatewayMsg, makePager, socIsAdmin, applyRoleClass, roleSansEcriturePartagee, LANG } from './core.js';
import { S } from './state.js';
import { coverageBadge, coverageHorizonNodes, provenanceBadge, currentFrom, currentTo, noeudsDeVizReglee, queryCount, runQuery, tableEl, vizElement } from './viz.js';
// P11.4-h : LE geste de copie de la console (mécanisme partagé).
import { boutonDeCopie } from './copie_et_selection.js';
import { prefGet, prefSet } from './prefs.js';
// P11.13-a : l'inventaire de ce que le produit porte DÉJÀ (modèles livrés, requêtes enregistrées,
// requêtes de règles), offert à qui compose un panneau. Ce module ne connaît rien d'un tableau de bord.
import { choisirDansLexistant } from './composer_depuis_lexistant.js';

// `P10.5-i` — CE QU'UN PANNEAU N'A PAS PU VOIR ARRIVE JUSQU'À L'ÉCRAN.
//
// Le démon publie `stats.coverage` sur TOUTE réponse de panneau — servie, mémorisée, ou figée dans un
// instantané. Sans ces deux fabriques, l'aveu arriverait dans le navigateur et ne s'afficherait nulle
// part : c'est le défaut déjà consigné « le démon avoue, la console n'écoute pas », et il serait
// recréé mot pour mot.
//
// LES DEUX GESTES SONT SÉPARÉS PARCE QU'ILS NE DISENT PAS LA MÊME CHOSE. Le BADGE ne paraît que si la
// fenêtre est réellement passée SOUS l'horizon (anti-fatigue : sinon douze panneaux sur douze le
// porteraient). La PHRASE d'horizon, elle, accompagne un corps SANS LIGNE — le cas fondateur de la clé :
// une courbe vide sur une fenêtre plus ancienne que l'horizon, que la console annonçait « aucune donnée
// sur la fenêtre », phrase FAUSSE (il y a eu des données ; elles n'existent plus).

/// Pose LES AVEUX d'une réponse de panneau, s'il y a lieu : la portée (l'horizon atteint) et la
/// provenance (un compte qui n'est qu'un plancher). `avant` = le nœud devant lequel les insérer
/// (`null` -> à la fin). Dans le corps d'un panneau l'aveu se lit AVANT ce qu'il qualifie ; sur une
/// carte d'instantané il se pose après le titre, qui est déjà là.
///
/// LES DEUX BADGES PASSENT PAR LE MÊME GESTE, parce que l'oubli était le même : le démon publiait
/// `provenance_non_derivee` + `rollup_note` et AUCUN module de la console ne les lisait — onze panneaux
/// livrés affichaient un nombre PLAFONNÉ par le top-N d'un pré-agrégé comme un nombre entier.
function poserLesAveuxDuPanneau(hote, stats, avant) {
  for (const b of [coverageBadge(stats), provenanceBadge(stats)]) {
    if (!b) continue;
    if (avant) hote.insertBefore(b, avant); else hote.appendChild(b);
  }
}

/// LE CORPS D'UN PANNEAU SANS LIGNE. `phrase` = le nœud texte que le site d'appel employait déjà — il
/// reste POSÉ CHEZ LUI (la garde du lexique le voit là où il est écrit), et cette fabrique décide
/// seulement s'il est CONSERVÉ ou REMPLACÉ. Aucun aveu -> comportement d'avant, à l'identique.
///
/// `laPhraseAffirmeUneAbsence` — CE QUE LA PHRASE DE L'APPELANT PRÉTEND, ET IL FAUT LE DIRE ICI. La
/// fabrique ne remplace une phrase que si elle est FAUSSE, et la fausseté dépend de ce qu'elle affirme :
///   * « aucune donnée sur la fenêtre » AFFIRME UNE ABSENCE -> faux dès que la fenêtre descend sous
///     l'horizon (il y a eu des données ; elles sont hors de portée) -> remplacé ;
///   * « … chargement (mesure en cours) » décrit un ÉTAT DU CALCUL, pas une absence -> il reste VRAI
///     quelle que soit la portée, et le jeter laissait l'écran dire « l'horizon s'arrête ici » sur un
///     corps que le démon déclare NON ENCORE CALCULÉ, pendant que la carte re-sonde toutes les 3 s.
/// Le défaut est asymétrique : retirer une phrase vraie et garder une phrase fausse sont la même faute.
function corpsSansLigne(stats, phrase, laPhraseAffirmeUneAbsence = true) {
  const d = document.createElement('div');
  d.className = 'muted';
  const h = coverageHorizonNodes(stats);
  if (!h) { d.appendChild(phrase); return d; }
  const dehors = !!(stats && stats.coverage && stats.coverage.older_outside_window === true);
  if (!dehors || !laPhraseAffirmeUneAbsence) d.append(phrase, document.createElement('br'));
  d.append(...h);
  return d;
}

// --- dashboards (P3) ---
/* state: editing, dashList, viewList, panelCards -> S (state.js) */ // mode édition + listes + cartes panneaux
const panelInflight = new Set();   // AbortControllers des panneaux en vol (bouton STOP de la vue Dashboards)
// #dash-stop visible TANT QU'un panneau est en vol ; load()'s finally rappelle ceci -> auto-masquage propre.
function syncDashStop(){ const sb=$('#dash-stop'); if(sb) sb.hidden = panelInflight.size===0; }
function stopDashboards() {
  panelInflight.forEach(c => { try { c.abort(); } catch (e) {} });
  panelInflight.clear();
  S.panelCards.forEach(card => { if (card._warmTimer) { clearTimeout(card._warmTimer); card._warmTimer = null; } });
  const sb = $('#dash-stop'); if (sb) sb.hidden = true;
}
function refreshDashboards() {
  const sb = $('#dash-stop'); if (sb) sb.hidden = false;
  S.panelCards.forEach(c => { if (c.isConnected && c._panel && c._panel.loaded) c._panel.reload(); });
  syncDashStop();   // load()'s finally rappelle syncDashStop -> le bouton se masque quand le dernier load se termine
}
// LAZY-LOAD des panneaux : on ne fait le fetch /api/panels/{id}/data QUE lorsque la carte entre dans le
// viewport (IntersectionObserver). Évite la RAFALE de N requêtes au chargement (tous les dashboards de la
// vue + tous leurs panneaux d'un coup), y compris ceux de l'onglet Dashboards encore caché, des dashboards
// repliés et des panneaux hors-écran. rootMargin 200px = précharge juste avant l'entrée à l'écran.
/* state: panelObserver -> S (state.js) */
function getPanelObserver() {
  if (S.panelObserver || !('IntersectionObserver' in window)) return S.panelObserver;
  S.panelObserver = new IntersectionObserver((entries) => {
    for (const en of entries) {
      const pn = en.target._panel; if (!pn) continue;
      pn.visible = en.isIntersecting;
      if (en.isIntersecting && !pn.loaded) { pn.loaded = true; pn.reload(); } // 1er fetch à l'apparition
    }
  }, { rootMargin: '200px' });
  return S.panelObserver;
}
// P5 : auto-refresh -> ne recharge QUE les panneaux suivant le global (window_s=0) ;
// un panneau a fenetre manuelle est fige (resync = remettre la fenetre a 0 dans l'edition).
// auto-refresh : ne recharge QUE les panneaux déjà chargés ET visibles (window_s===0) -> ne force pas le
// fetch des panneaux hors-écran/cachés à chaque tick (le lazy-load s'en charge à leur apparition).
function refreshPanels() { S.panelCards.forEach(c => { const pn = c._panel; if (c.isConnected && pn && pn.window_s === 0 && pn.loaded && pn.visible) pn.reload(); }); }
const VIZOPTS = [{ value: 'table', label: 'Table' }, { value: 'bar', label: 'Barres' }, { value: 'line', label: 'Courbe' }, { value: 'stat', label: 'Stat' }, { value: 'gauge', label: 'Jauge' }, { value: 'pie', label: 'Camembert' }, { value: 'donut', label: 'Donut' }, { value: 'heatmap', label: 'Heatmap' }, { value: 'histogram', label: 'Histogramme' }];
// `P11.17-b` — L'ACCÈS À CE QUI EST DÉJÀ ENREGISTRÉ PART DE L'ENDROIT OÙ L'ON COMPOSE, ET PORTE LE NOM DE
// CE QU'IL OFFRE. La console offrait DEUX entrées voisines pour un même but, et une seule aboutissait :
// l'icône « + » (« Ajouter un panneau »), celle qu'on prend spontanément, ouvrait le formulaire nu ; et un
// second bouton, seul à mener à l'inventaire, était libellé « Partir de l'existant » — une formule qui ne
// contient aucun des mots que cherche quelqu'un qui veut ses MODÈLES ou ses REQUÊTES ENREGISTRÉES. Elles ne
// différaient pas que par le nom : la première n'était pas conditionnée au droit d'édition, la seconde
// l'était, donc il existait un état où l'on voyait l'entrée qui ne mène nulle part sans voir celle qui mène
// à l'inventaire. Il n'y a plus qu'UNE entrée — celle qu'on prend — et l'inventaire s'ouvre DEPUIS la
// fenêtre de composition, sous un libellé qui nomme les deux stocks qu'on y cherche. Plus de piège, et plus
// d'asymétrie de droit : il n'y a plus deux contrôles à conditionner.
//
// P11.13-a — LA FENÊTRE DE CHOIX NE S'IMBRIQUE PAS dans celle du panneau : la modale partagée ferme toute
// autre modale à son ouverture, donc imbriquer perdrait la promesse de la première. La composition est donc
// MISE DE CÔTÉ (ce qui est saisi est relevé avant de fermer), le choix s'ouvre seul, puis la composition
// revient — enrichie du choix, ou intacte si la fenêtre de choix est abandonnée. Rien n'est perdu par le
// détour : c'est ce qui permet à l'accès de vivre DANS le formulaire plutôt qu'avant lui.
function accesALexistant(relever) {
  const corps = document.createElement('div');
  const b = document.createElement('button');
  b.type = 'button'; b.className = 'btn dashcompose';
  // Bilingue PAR CONSTRUCTION (les deux langues sont ici, côte à côte) plutôt que par le lexique : le
  // libellé porte les mots que l'exploitant cherche, dans l'une et l'autre langue.
  b.textContent = LANG === 'en' ? 'Templates and saved queries…' : 'Modèles et requêtes enregistrées…';
  b.title = 'Composer un panneau depuis un modèle livré, une requête enregistrée ou une règle de détection';
  b.onclick = () => {
    const f = b.closest('form'); if (!f) return;
    const saisie = {};
    f.querySelectorAll('[data-n]').forEach(el => { saisie[el.dataset.n] = el.type === 'checkbox' ? el.checked : el.value; });
    relever(saisie);
    const annuler = f.querySelector('.m-cancel'); if (annuler) annuler.click();
  };
  corps.appendChild(b);
  return corps;
}

// `prefill` (P11.13-a) : ce qu'une définition existante apporte en plus de son texte — son nom, sa
// visualisation, et sa NATURE telle que le démon l'a déclarée. `is_soql` déclaré vaut mieux que la
// devinette locale : une règle en SQL brut dont le texte porte une barre verticale serait prise pour du
// GXQL par l'heuristique, et le panneau ne compilerait pas. La devinette reprend la main dès que le
// texte est ÉDITÉ — la nature déclarée ne vaut plus pour une requête qui n'est plus celle-là.
async function createPanelModal(did, query = '', prefill = {}) {
  // #54 — LIBRARY PANELS : proposer de RÉFÉRENCER une définition réutilisable (édité une fois, à jour partout).
  let libs = [];
  try { libs = (await api('/library-panels')).library_panels || []; } catch (e) {}
  const libOpts = [{ value: '', label: '— aucun (panneau autonome) —' }, ...libs.map(l => ({ value: String(l.id), label: l.name + ' (' + l.viz + ')' }))];
  // `P11.17-b` — l'accès à l'inventaire vit DANS cette fenêtre (voir `accesALexistant`). `saisie` reste
  // `null` tant qu'on n'y touche pas : c'est ce qui distingue un abandon de la fenêtre d'un détour vers
  // l'inventaire, deux sorties que la modale partagée rend toutes deux par `null`.
  let saisie = null;
  const r = await modal({
    title: 'Nouveau panneau', okText: 'Créer', body: accesALexistant(v => { saisie = v; }), fields: [
      { name: 'library_panel_id', label: 'Panneau de bibliothèque (réutilisable)', type: 'select', value: prefill.library_panel_id || '', options: libOpts },
      { name: 'title', label: 'Titre', required: true, value: prefill.title || 'Panneau' },
      { name: 'query', label: 'Requête (GXQL ou SQL) — ignorée si un panneau de bibliothèque est choisi', type: 'textarea', required: false, value: query, placeholder: 'search source=sudo | stats count by source' },
      { name: 'viz', label: 'Visualisation', type: 'select', value: prefill.viz || 'table', options: VIZOPTS },
      { name: 'visibility', label: 'Panneau', type: 'select', value: prefill.visibility || 'shared', options: [{ value: 'shared', label: 'public' }, { value: 'private', label: 'privé' }] },
      { name: 'query_private', label: 'Requête privée (cacher le texte aux autres)', type: 'checkbox', value: !!prefill.query_private },
      { name: 'drill', label: 'Requête au clic / drill (optionnel : $value, $from, $to)', type: 'textarea', value: prefill.drill || '', placeholder: 'search source=$value | table ts,source,src_ip,message' },
    ],
  });
  // DÉTOUR PAR L'INVENTAIRE, puis retour à la composition. Le choix écrase titre, requête et nature ; tout
  // le reste de ce qui était saisi est rendu tel quel — un abandon du choix ne coûte donc rien non plus.
  // La NATURE déclarée ne survit au détour que si le texte n'a pas été touché : elle ne vaut que pour la
  // requête qu'elle décrit (même règle qu'à la validation, plus bas).
  if (r === null && saisie) {
    const c = await choisirDansLexistant();
    const natureTenue = prefill.is_soql !== undefined && String(saisie.query || '').trim() === String(query || '').trim();
    return createPanelModal(did, c ? c.requete : (saisie.query || ''), {
      title: c ? c.titre : saisie.title,
      viz: c ? c.viz : saisie.viz,
      is_soql: c ? c.is_soql : (natureTenue ? prefill.is_soql : undefined),
      library_panel_id: saisie.library_panel_id,
      visibility: saisie.visibility,
      query_private: saisie.query_private,
      drill: saisie.drill,
    });
  }
  if (!r) return;
  const libId = Number(r.library_panel_id) || 0;
  // P7.13-a — CE COMMENTAIRE AFFIRMAIT LE CONTRAIRE ET C'EST CE RAISONNEMENT QUI A OUVERT LE TROU : il
  // disait « pas de garde SQL brut ici, le library_panel a été gardé à SA création ». Or la garde de la
  // création vise l'AUTEUR de la définition, jamais celui qui CHOISIT de l'exécuter. Un editor pouvait
  // donc référencer une définition SQL brut d'admin et en lire le résultat (mesuré 2026-08-03 : 200,
  // 2 lignes de la table `user`). Le SERVEUR tranche désormais (`panel_create`/`panel_update` résolvent
  // panneau ∪ bibliothèque AVANT la porte) : ce chemin peut légitimement répondre 403, et l'UI le montre.
  // Sinon, panneau autonome : requête requise + garde SQL brut côté saisie.
  if (libId) {
    // Le refus du serveur doit être VU : sans ce catch, un 403 se perdait en rejet non traité (la
    // fenêtre se fermait « comme si » le panneau avait été créé). Une garde invisible n'en est pas une.
    try {
      await apiSend('/panels', 'POST', { dashboard_id: Number(did), title: r.title.trim(), library_panel_id: libId, query: '', is_soql: true, visibility: r.visibility });
    } catch (e) { toast('Panneau non créé : ' + ((e && e.message) || e), 'bad'); return; }
    await loadDashboards(); toast('Panneau (bibliothèque) créé', 'ok'); return;
  }
  const qq = r.query.trim(); if (!qq) { toast('Requête requise (ou choisis un panneau de bibliothèque).', 'bad'); return; }
  // La NATURE déclarée par le démon fait foi tant que le texte n'a pas bougé ; sinon l'heuristique.
  const intacte = prefill.is_soql !== undefined && qq === String(query || '').trim();
  const isSoql = intacte ? !!prefill.is_soql : (/^\s*search\b/i.test(qq) || qq.includes('|'));
  // FAILLE B (UI) — un panneau en SQL brut (saisie non-GXQL) est réservé admin (miroir serveur panel_create).
  if (!isSoql && !socIsAdmin()) { toast('SQL brut réservé à l\'administrateur (utilisez GXQL)', 'bad'); return; }
  try {
    await apiSend('/panels', 'POST', { dashboard_id: Number(did), title: r.title.trim(), query: qq, is_soql: isSoql, viz: r.viz, visibility: r.visibility, query_private: !!r.query_private, drill: (r.drill || '').trim() });
  } catch (e) { toast('Panneau non créé : ' + ((e && e.message) || e), 'bad'); return; }
  await loadDashboards(); toast('Panneau créé', 'ok');
}
// La VUE courante affiche TOUS ses dashboards ; chaque dashboard = une tuile (carte) avec sa grille de panneaux.
async function loadDashboards() {
  const wrap = $('#dashview'); if (!wrap) return;
  try {
    const view = $('#view') ? $('#view').value : '';
    const data = await api('/dashboards' + (view ? '?view=' + encodeURIComponent(view) : ''));
    S.dashList = data.dashboards || [];
    applyRoleClass(data.role); // reflète le rôle sur <body> -> le CSS masque les contrôles d'écriture
    renderView();
  } catch (e) {}
}
// rafraichit seulement les DONNEES des panneaux (zoom / intervalle) sans rebatir le layout
// changement de plage/zoom : recharge les panneaux VISIBLES tout de suite ; INVALIDE les non-visibles
// (loaded=false) -> ils se rechargeront avec la nouvelle plage à leur prochaine apparition (pas de rafale).
function loadDashboard() {
  S.panelCards.forEach(c => { const pn = c._panel; if (pn && pn.window_s === 0 && !pn.visible) pn.loaded = false; });
  refreshPanels();
}
// `P11.4-m` — LES DEUX PERSISTANCES D'ETAT DE CETTE VUE, GATEES EN UN SEUL ENDROIT. Plier une tuile ou
// changer la visualisation d'un panneau produit un effet LOCAL permis a tout role, mais la persistance est
// une mutation editoriale (`/api/dashboard/{id}`, `/api/panels/{id}` -> editor+ dans la table du demon) : un
// lecteur y recevait un 403 muet a chaque geste. Le refus est pose ICI, sur la persistance, et non sur les
// controles — les marquer d'ecriture aurait coupe le geste permis. La vue locale suit ; rien n'est envoye.
function patchDash(id, body) { return roleSansEcriturePartagee() ? Promise.resolve(null) : apiSend('/dashboard/' + id, 'POST', body); }
// #62 — FAVORIS de dashboards (per-user), stockés dans le store de préférences self-scoped (/api/prefs,
// clé `favDash` = liste d'ids). AUCUN schéma dashboard partagé n'est touché (les favoris sont propres à
// chaque compte). Les favoris remontent en tête (tri STABLE, hors mode édition -> jamais de conflit avec le
// réordonnancement manuel persisté) et portent une étoile pleine.
function favDashIds() { const a = prefGet('favDash', []); return Array.isArray(a) ? a.map(Number) : []; }
function isFavDash(id) { return favDashIds().includes(Number(id)); }
function toggleFavDash(id) {
  id = Number(id);
  const cur = favDashIds().filter(x => x !== id);
  if (!isFavDash(id)) cur.unshift(id);   // ajout -> en tête (ordre = récence d'ajout) ; retrait -> déjà filtré
  prefSet('favDash', cur);
}
// largeur d'une tuile = c/4 de la ligne (flex-basis) ; flex-grow=1 -> remplit la largeur restante, passe a la ligne quand plein
const tileBasis = c => 'calc(' + (Math.max(1, Math.min(4, c)) * 25) + '% - 12px)';
function renderView() {
  const wrap = $('#dashview'); if (!wrap) return;
  wrap.classList.toggle('editing', S.editing);
  if (S.panelObserver) { S.panelObserver.disconnect(); S.panelObserver = null; } // repart propre (cartes recréées)
  S.panelCards = [];
  wrap.replaceChildren();
  if (!S.dashList.length) {
    const es = document.createElement('div'); es.className = 'emptystate';
    es.append(Object.assign(document.createElement('div'), { textContent: 'Aucun dashboard' + ($('#view') && $('#view').value ? ' dans cette vue' : '') + '.' }));
    const b = document.createElement('button'); b.type = 'button'; b.className = 'btn'; b.textContent = '+ Dashboard'; b.onclick = () => $('#dash-new').click(); es.appendChild(b); // P11.4-b : classe partagée
    wrap.replaceChildren(es); return;
  }
  // #62 — hors mode édition, les FAVORIS remontent en tête (tri STABLE : ordre serveur préservé DANS chaque
  // groupe). En mode édition on garde l'ordre canonique S.dashList (le drag-réordonne persiste par index).
  let list = S.dashList;
  if (!S.editing) {
    const favs = favDashIds();
    list = S.dashList.map((d, i) => [d, i]).sort((a, b) => {
      const fa = favs.includes(Number(a[0].id)), fb = favs.includes(Number(b[0].id));
      if (fa !== fb) return fa ? -1 : 1;
      return a[1] - b[1];
    }).map(x => x[0]);
  }
  list.forEach(d => wrap.appendChild(renderDashboard(d)));
}
function renderDashboard(d) {
  const editable = d.editable !== false;
  const tile = document.createElement('section'); tile.className = 'dashtile card2'; tile.dataset.id = d.id;
  const cols = Math.max(1, Math.min(4, d.cols || 2));
  tile.style.flexBasis = tileBasis(cols);
  if (d.collapsed) tile.classList.add('collapsed');
  // --- en-tete : plier + (poignee) + titre + outils ---
  const head = document.createElement('div'); head.className = 'dashtile-head';
  const chev = document.createElement('button'); chev.type = 'button'; chev.className = 'chev picon'; chev.title = 'Plier / deplier'; chev.innerHTML = ic(d.collapsed ? 'chevright' : 'chevdown');
  const grip = document.createElement('span'); grip.className = 'grip editonly'; grip.innerHTML = ic('grip'); grip.title = 'Glisser l\'en-tete pour reordonner';
  const h = document.createElement('h3'); h.textContent = d.name;
  const meta = document.createElement('span'); meta.className = 'dashmeta'; meta.textContent = `${d.panels} panneau(x)${d.visibility === 'private' ? ' - prive' : ''}`;
  const tools = document.createElement('div'); tools.className = 'paneltools';
  // #62 — étoile FAVORI (tous rôles : préférence perso, pas une mutation partagée). Toggle instantané : on
  // repeint l'étoile et, à l'ajout, on remonte la tuile en tête sans recharger les panneaux (le tri complet
  // favoris-en-tête s'applique au prochain rendu de la vue).
  const fav = document.createElement('button'); fav.type = 'button'; fav.className = 'picon favstar';
  const paintFav = () => { const on = isFavDash(d.id); fav.classList.toggle('on', on); fav.innerHTML = ic(on ? 'starfill' : 'star'); fav.title = on ? 'Retirer des favoris' : 'Ajouter aux favoris'; };
  paintFav();
  fav.onclick = () => {
    const wasFav = isFavDash(d.id);
    toggleFavDash(d.id); paintFav();
    if (!wasFav) { const w = $('#dashview'); if (w && tile.parentElement === w) w.insertBefore(tile, w.firstChild); }
  };
  // `P11.4-m` — LE REFUS SE DECLARE SUR LE CONTROLE, IL NE SE DEDUIT PLUS DU CONTENEUR. La feuille effacait
  // pour un lecteur tout `.picon` pose dans `.paneltools` : elle emportait l'etoile de favori, les deux
  // rafraichissements, l'arret, les exports et l'ouverture dans l'editeur — sept gestes que le demon ACCORDE.
  // Les outils ci-dessous portent donc `crud-btn` un par un, et SEULEMENT ceux dont la route est bornee a
  // `editor+` (`/api/panels`, `/api/dashboard/{id}`, `/api/dashboard-snapshots`) : ils restent visibles,
  // inertes et motives (grammaire de `P11.4-l`). Ce qui ne porte pas la marque reste PERMIS, comme le serveur.
  // `P11.17-b` — UN SEUL geste de création de panneau. Il y en avait deux côte à côte pour le même but, et
  // celui-ci — le seul qu'on prenne — était celui qui n'offrait AUCUN accès aux requêtes enregistrées. Le
  // second est retiré : ce qu'il donnait s'ouvre désormais depuis la fenêtre de composition (`accesALexistant`),
  // sous un libellé qui nomme les stocks. Une entrée qui ne mène pas au but ne subsiste donc plus à côté
  // d'une autre qui y mène — et l'asymétrie de droit entre les deux disparaît avec la seconde entrée.
  const addp = document.createElement('button'); addp.type = 'button'; addp.className = 'picon crud-btn'; addp.innerHTML = ic('plus'); addp.title = 'Ajouter un panneau';
  // refresh PAR DASHBOARD (non editonly : un viewer peut rafraîchir) -> recharge UNIQUEMENT les panneaux de CETTE grille
  const dref = document.createElement('button'); dref.type = 'button'; dref.className = 'picon'; dref.innerHTML = ic('refresh'); dref.title = 'Rafraîchir ce dashboard';
  dref.onclick = () => {
    const sb = $('#dash-stop'); if (sb) sb.hidden = false;
    grid.querySelectorAll('.panel').forEach(c => { if (c._panel && c._panel.loaded) c._panel.reload(); });
    syncDashStop();
  };
  const ren = document.createElement('button'); ren.type = 'button'; ren.className = 'picon editonly crud-btn'; ren.innerHTML = ic('pencil'); ren.title = 'Renommer le dashboard';
  const wsel = document.createElement('select'); wsel.className = 'picon editonly crud-btn'; wsel.title = 'Largeur (colonnes)';
  [1, 2, 3, 4].forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n + ' col'; wsel.appendChild(o); });
  wsel.value = String(cols);
  const del = document.createElement('button'); del.type = 'button'; del.className = 'picon editonly crud-btn'; del.innerHTML = ic('x'); del.title = 'Supprimer le dashboard';
  // EXPORT dashboard : PDF (impression de la surface #dashboards) ; CSV/JSON se font par panneau.
  const dpdf = document.createElement('button'); dpdf.type = 'button'; dpdf.className = 'picon'; dpdf.innerHTML = ic('print'); dpdf.title = 'Imprimer / exporter ce dashboard en PDF';
  dpdf.onclick = () => exportPDF('dashboards');
  // #54 — INSTANTANÉ : capture le rendu courant (données DÉJÀ masquées côté serveur au rôle de l'appelant),
  // partageable en lecture seule via un token. editor+ (le bouton n'apparaît qu'à eux ; le serveur re-garde).
  const dsnap = document.createElement('button'); dsnap.type = 'button'; dsnap.className = 'picon editonly crud-btn'; dsnap.innerHTML = ic('save'); dsnap.title = 'Capturer un instantané partageable (lecture seule)';
  dsnap.onclick = () => captureSnapshot(d);
  tools.append(fav, dref, addp, dpdf);
  if (editable) tools.append(dsnap, ren, wsel, del);
  head.append(chev, grip, h, meta, tools);
  tile.appendChild(head);
  // --- corps : grille de panneaux ---
  const body = document.createElement('div'); body.className = 'dashtile-body';
  const grid = document.createElement('div'); grid.className = 'dashgrid'; grid.textContent = '...'; body.appendChild(grid);
  tile.appendChild(body);
  if (d.height > 0) { body.style.height = d.height + 'px'; body.style.overflow = 'auto'; }
  // un dashboard REPLIÉ ne charge même pas sa liste de panneaux : différé jusqu'à la 1re expansion.
  if (!d.collapsed) loadPanelsInto(grid, d);
  else grid._deferredLoad = () => { grid._deferredLoad = null; loadPanelsInto(grid, d); };
  chev.onclick = () => {
    const c = !tile.classList.contains('collapsed');
    tile.classList.toggle('collapsed', c); chev.innerHTML = ic(c ? 'chevright' : 'chevdown');
    d.collapsed = c; // garde dashList a jour -> les re-render ne reviennent pas a l'ancien etat
    if (!c && grid._deferredLoad) grid._deferredLoad(); // expansion -> charge les panneaux (1re fois)
    if (editable) patchDash(d.id, { collapsed: c });
  };
  addp.onclick = () => createPanelModal(d.id, ($('#sql') && $('#sql').value.trim()) || '');
  ren.onclick = async () => {
    const r = await modal({ title: 'Renommer le dashboard', okText: 'Enregistrer', fields: [{ name: 'name', label: 'Nom', required: true, value: d.name }], validate: v => S.dashList.some(x => x.id !== d.id && x.name === v.name.trim()) ? 'Un dashboard porte deja ce nom.' : null });
    if (!r) return; await patchDash(d.id, { name: r.name.trim() }); loadDashboards();
  };
  wsel.onchange = () => { const n = Number(wsel.value); d.cols = n; tile.style.flexBasis = tileBasis(n); patchDash(d.id, { cols: n }); };
  del.onclick = async () => { if (await confirmModal('Supprimer ce dashboard et ses panneaux ?', { danger: true })) { await apiSend('/dashboard/' + d.id, 'DELETE'); loadDashboards(); } };
  if (editable) {
    // coin de redimensionnement : hauteur px + largeur 1-4 col (calee sur le quart de ligne = garde-fou)
    const corner = document.createElement('div'); corner.className = 'dcorner editonly'; corner.title = 'Redimensionner (glisser)';
    tile.appendChild(corner);
    corner.onmousedown = e => {
      e.preventDefault();
      const y0 = e.clientY, h0 = body.clientHeight || body.scrollHeight, gw = tile.parentElement;
      const slot = gw ? gw.clientWidth / 4 : 320; // largeur d'une colonne (quart de ligne)
      const left = tile.getBoundingClientRect().left;
      let ncols = cols, nh = h0;
      const mv = ev => {
        nh = Math.max(120, h0 + ev.clientY - y0); body.style.height = nh + 'px'; body.style.overflow = 'auto';
        ncols = Math.max(1, Math.min(4, Math.round((ev.clientX - left) / slot)));
        tile.style.flexBasis = tileBasis(ncols); wsel.value = String(ncols);
      };
      const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); d.cols = ncols; d.height = Math.round(nh); patchDash(d.id, { cols: ncols, height: Math.round(nh) }); };
      document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    };
    // glisser-deposer pour reordonner (uniquement en mode edition ; poignee = en-tete)
    head.draggable = true;
    head.addEventListener('dragstart', e => { if (!S.editing) { e.preventDefault(); return; } e.dataTransfer.setData('text/plain', String(d.id)); e.dataTransfer.effectAllowed = 'move'; tile.classList.add('dragging'); });
    head.addEventListener('dragend', () => tile.classList.remove('dragging'));
    tile.addEventListener('dragover', e => { if (S.editing) { e.preventDefault(); tile.classList.add('dragover'); } });
    tile.addEventListener('dragleave', () => tile.classList.remove('dragover'));
    tile.addEventListener('drop', e => {
      e.preventDefault(); tile.classList.remove('dragover');
      if (!S.editing) return;
      const from = Number(e.dataTransfer.getData('text/plain'));
      if (from && from !== d.id) reorderDash(from, d.id);
    });
  }
  return tile;
}
async function loadPanelsInto(grid, d) {
  try {
    const j = await api('/dashboard/' + d.id);
    const panels = j.panels || [];
    if (!panels.length) {
      const es = document.createElement('div'); es.className = 'emptystate';
      es.append(Object.assign(document.createElement('div'), { textContent: 'Dashboard vide.' }));
      if (j.editable !== false) {
        // `P11.17-b` — un seul geste ici aussi. Un dashboard VIDE est l'endroit où l'on a le moins envie de
        // retaper une requête qui existe ailleurs, et c'est précisément pour cela que l'accès à l'existant
        // ne doit pas être un BOUTON VOISIN qu'on peut ne pas voir : il est dans la fenêtre qui s'ouvre.
        const b = document.createElement('button'); b.type = 'button'; b.className = 'btn'; b.textContent = '+ Ajouter un panneau'; b.onclick = () => createPanelModal(d.id, ($('#sql') && $('#sql').value.trim()) || ''); es.appendChild(b);
      }
      grid.replaceChildren(es); return;
    }
    const frag = document.createDocumentFragment();
    for (const p of panels) { const c = await renderPanel(p, j.editable !== false); S.panelCards.push(c); frag.appendChild(c); }
    grid.replaceChildren(frag);
  } catch (e) { grid.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'erreur : ' + e.message })); }
}
// reordonne les dashboards (place `from` juste avant `target`) et persiste les positions
function reorderDash(fromId, targetId) {
  const arr = S.dashList.slice();
  const fi = arr.findIndex(x => x.id === fromId);
  if (fi < 0) return;
  const [m] = arr.splice(fi, 1);
  const ti = arr.findIndex(x => x.id === targetId);
  arr.splice(ti < 0 ? arr.length : ti, 0, m);
  arr.forEach((x, i) => { if (x.position !== i) { x.position = i; patchDash(x.id, { position: i }); } });
  S.dashList = arr; renderView();
}
function patchPanel(id, body) { return roleSansEcriturePartagee() ? Promise.resolve(null) : apiSend('/panels/' + id, 'POST', body); }
// reordonne les PANNEAUX dans une grille de dashboard (place `from` avant `target`) et persiste position
function reorderPanels(grid, fromId, targetId, after) {
  const panels = () => [...grid.children].filter(c => c.classList && c.classList.contains('panel'));
  const cards = panels();
  const fromCard = cards.find(c => c._panelId === fromId), targetCard = cards.find(c => c._panelId === targetId);
  if (!fromCard || !targetCard || fromCard === targetCard) return;
  grid.insertBefore(fromCard, after ? targetCard.nextSibling : targetCard); // avant/apres selon le curseur
  panels().forEach((c, i) => patchPanel(c._panelId, { position: i }));
}
// EXPORT PANNEAU : menu CSV/JSON sur les données courantes du panneau (result = {columns, rows}).
function panelExport(anchor, p, result) {
  if (!result || !result.rows || !result.rows.length) { toast('Aucune donnée à exporter', 'info'); return; }
  const columns = result.columns || [];
  const cols = columns.map(c => ({ key: c, label: c }));
  const objs = result.rows.map(row => { const o = {}; columns.forEach((c, i) => { o[c] = row[i]; }); return o; });
  const base = 'panneau-' + String(p.title || p.id).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 40);
  miniMenu(anchor, [
    { label: 'CSV', fn: () => downloadText(`plume-${base}-${tsSlug()}.csv`, 'text/csv;charset=utf-8', toCSV(cols, objs)) },
    { label: 'JSON', fn: () => downloadText(`plume-${base}-${tsSlug()}.json`, 'application/json', JSON.stringify(objs, null, 2)) },
  ]);
}
async function renderPanel(p, editable = true) {
  const card = document.createElement('section'); card.className = 'card panel'; card._panelId = p.id;
  const head = document.createElement('div'); head.className = 'panelhead';
  const pgrip = document.createElement('span'); pgrip.className = 'pgrip editonly'; pgrip.innerHTML = ic('grip'); pgrip.title = 'Glisser pour deplacer le panneau'; pgrip.draggable = true;
  const t = document.createElement('h3'); t.textContent = p.title;
  const tools = document.createElement('div'); tools.className = 'paneltools';
  let curViz = p.viz;
  const seg = document.createElement('div'); seg.className = 'seg'; seg.setAttribute('role', 'group'); seg.setAttribute('aria-label', 'Visualisation');
  const btns = {};
  const VIZIC = { table: 'table', bar: 'bars', line: 'activity', stat: 'hash', gauge: 'gauge', pie: 'pie', donut: 'pie', heatmap: 'grid', histogram: 'histogram' };
  [['table', 'Table'], ['bar', 'Barres'], ['line', 'Courbe'], ['stat', 'Stat'], ['gauge', 'Jauge'], ['pie', 'Camembert'], ['donut', 'Donut'], ['heatmap', 'Heatmap'], ['histogram', 'Histogramme']].forEach(([m, lab]) => {
    const b = document.createElement('button'); b.innerHTML = ic(VIZIC[m]); b.title = lab; b.setAttribute('aria-label', lab);
    if (m === curViz) b.classList.add('on');
    b.onclick = () => {
      curViz = m; Object.values(btns).forEach(x => x.classList.remove('on')); b.classList.add('on'); draw();
      if (editable) patchPanel(p.id, { viz: m });
    };
    btns[m] = b; seg.appendChild(b);
  });
  const open = document.createElement('button'); open.className = 'picon'; open.innerHTML = ic('ext'); open.title = 'Ouvrir dans Explore';
  open.onclick = () => { $('#sql').value = p.query; location.hash = 'explore'; runQuery(); };
  // `P11.4-m` — meme declaration qu'en tete de tuile : seuls les outils dont la route est bornee a `editor+`
  // (`/api/panels/{id}`) portent la marque ; ouvrir dans l'editeur, rafraichir, arreter et exporter restent
  // PERMIS a un lecteur, ce que la borne serveur dit deja (lecture, ou aucun appel du tout).
  const edit = document.createElement('button'); edit.className = 'picon editonly crud-btn'; edit.innerHTML = ic('pencil'); edit.title = 'Éditer le panneau';
  const del = document.createElement('button'); del.className = 'picon editonly crud-btn'; del.innerHTML = ic('x'); del.title = 'Supprimer le panneau';
  del.onclick = async () => { if (await confirmModal('Supprimer ce panneau ?', { danger: true })) { await apiSend('/panels/' + p.id, 'DELETE'); loadDashboards(); } };
  const wsel = document.createElement('select'); wsel.className = 'picon editonly crud-btn'; wsel.title = 'Largeur (colonnes)';
  [1, 2, 3, 4].forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n + ' col'; wsel.appendChild(o); });
  wsel.value = String(p.cols || 1);
  wsel.onchange = () => { const n = Number(wsel.value); card.style.flexBasis = tileBasis(n); patchPanel(p.id, { cols: n }); };
  tools.appendChild(seg);
  // refresh + STOP par panneau (non editonly : un viewer peut rafraîchir / arrêter SON chargement)
  const pref = document.createElement('button'); pref.type = 'button'; pref.className = 'picon'; pref.innerHTML = ic('refresh'); pref.title = 'Rafraîchir ce panneau'; pref.onclick = () => load();
  const pstop = stopBtn('Arrêter ce panneau', () => { if (card._loadCtrl) { try { card._loadCtrl.abort(); } catch (e) {} } }); pstop.hidden = true;
  // EXPORT panneau (CSV / JSON) : sérialise les données DÉJÀ chargées (panel_data, déjà caviardé/gated).
  const pexp = document.createElement('button'); pexp.type = 'button'; pexp.className = 'picon'; pexp.innerHTML = ic('download'); pexp.title = 'Exporter les données de ce panneau (CSV / JSON)';
  pexp.onclick = (e) => { e.stopPropagation(); panelExport(pexp, p, result); };
  tools.append(pref, pstop, pexp);
  if (p.query) tools.appendChild(open);          // pas d'ouverture si la requête est privée (texte masqué)
  if (editable) tools.append(wsel, edit, del);
  head.append(pgrip, t, tools); card.appendChild(head);
  // deplacer le panneau dans son dashboard (glisser la poignee ; mode Edition uniquement)
  if (editable) {
    pgrip.addEventListener('dragstart', e => { if (!S.editing) { e.preventDefault(); return; } e.dataTransfer.setData('text/plain', 'panel:' + p.id); e.dataTransfer.effectAllowed = 'move'; card.classList.add('dragging'); });
    pgrip.addEventListener('dragend', () => card.classList.remove('dragging'));
    card.addEventListener('dragover', e => { if (!S.editing) return; e.preventDefault(); e.stopPropagation(); card.classList.add('dragover'); });
    card.addEventListener('dragleave', () => card.classList.remove('dragover'));
    card.addEventListener('drop', e => {
      e.preventDefault(); e.stopPropagation(); card.classList.remove('dragover');
      if (!S.editing) return;
      const dt = e.dataTransfer.getData('text/plain');
      if (!dt.startsWith('panel:')) return; // ignore un drag de dashboard
      const fromId = Number(dt.slice(6));
      if (fromId && fromId !== p.id && card.parentElement) {
        const r = card.getBoundingClientRect();
        reorderPanels(card.parentElement, fromId, p.id, (e.clientX - r.left) > r.width / 2);
      }
    });
  }
  card.style.flexBasis = tileBasis(p.cols || 1);
  const vistag = p.visibility === 'private' ? '  [privé]' : '';
  const qline = document.createElement('code'); qline.className = 'panelq';
  qline.textContent = (p.query || '(requête privée)') + (p.window_s ? `  - fenêtre fixe ${p.window_s}s (épinglé)` : '') + vistag;
  qline.title = (p.is_soql ? 'GXQL' : 'SQL') + (p.window_s ? " - fenêtre fixe : ignore l'intervalle/refresh global (édite, mets 0 pour resync)" : ''); card.appendChild(qline);
  // formulaire d'édition par panneau (titre / requête / viz / fenêtre)
  const ef = document.createElement('form'); ef.className = 'ruleform'; ef.hidden = true;
  ef.innerHTML = `<input class="pe-title" placeholder="titre"><textarea class="pe-query" rows="2" spellcheck="false"></textarea>`
    + `<div class="rf-row"><label>Viz <select class="pe-viz"><option value="table">Table</option><option value="bar">Barres</option><option value="line">Courbe</option><option value="stat">Stat</option><option value="gauge">Jauge</option><option value="pie">Camembert</option><option value="donut">Donut</option><option value="heatmap">Heatmap</option><option value="histogram">Histogramme</option></select></label>`
    + `<label>Fenêtre(s) (0 = globale) <input class="pe-win" type="number" value="0"></label></div>`
    + `<div class="rf-row"><label>Panneau <select class="pe-vis"><option value="shared">public</option><option value="private">privé</option></select></label>`
    + `<label><input class="pe-qpriv" type="checkbox"> requête privée (cacher le texte aux autres)</label></div>`
    + `<label class="pe-drill-l">Requête au clic / drill (vide = défaut) <textarea class="pe-drill" rows="2" spellcheck="false" placeholder="search source=$value | table ts,source,src_ip,message"></textarea></label>`
    + `<div class="rf-hint">Marqueurs au clic : $value (valeur cliquée, mise entre guillemets) ; $from / $to (bornes du bucket). Un clic temporel restreint déjà la fenêtre au bucket.</div>`
    + `<div class="rf-actions"><button type="submit">Enregistrer</button><button type="button" class="pe-cancel">Annuler</button></div>`;
  ef.querySelector('.pe-title').value = p.title; ef.querySelector('.pe-query').value = p.query; ef.querySelector('.pe-viz').value = p.viz; ef.querySelector('.pe-win').value = p.window_s || 0;
  ef.querySelector('.pe-vis').value = p.visibility || 'shared'; ef.querySelector('.pe-qpriv').checked = !!p.query_private;
  ef.querySelector('.pe-drill').value = p.drill || '';
  edit.onclick = () => { ef.hidden = !ef.hidden; };
  ef.querySelector('.pe-cancel').onclick = () => { ef.hidden = true; };
  ef.onsubmit = async (e) => {
    e.preventDefault();
    const q = ef.querySelector('.pe-query').value.trim();
    const isSoql = /^\s*search\b/i.test(q) || q.includes('|');
    // FAILLE B (UI) — éditer un panneau en SQL brut (saisie non-GXQL) est réservé admin (miroir serveur panel_update).
    if (!isSoql && !socIsAdmin()) { toast('SQL brut réservé à l\'administrateur (utilisez GXQL)', 'bad'); return; }
    const upd = { title: ef.querySelector('.pe-title').value.trim() || 'Panneau', query: q, viz: ef.querySelector('.pe-viz').value, is_soql: isSoql, window_s: Number(ef.querySelector('.pe-win').value) || 0, visibility: ef.querySelector('.pe-vis').value, query_private: ef.querySelector('.pe-qpriv').checked, drill: ef.querySelector('.pe-drill').value.trim() };
    // Le refus du serveur doit être VU (P7.13-a) : depuis que la porte « SQL brut = admin » juge la
    // définition RÉELLEMENT EXÉCUTÉE, éditer un panneau qui exécute une définition de bibliothèque en
    // SQL brut répond 403 — sans ce catch, l'enregistrement se perdait en rejet non traité.
    try { await patchPanel(p.id, upd); } catch (e) { toast('Panneau non enregistré : ' + ((e && e.message) || e), 'bad'); return; }
    loadDashboards();
  };
  card.appendChild(ef);
  const prog = document.createElement('div'); prog.className = 'tableprog'; prog.hidden = true; prog.setAttribute('aria-hidden', 'true'); card.appendChild(prog);
  const body = document.createElement('div'); body.className = 'panelbody'; body.textContent = '...'; card.appendChild(body);
  if (p.height > 0) { body.style.height = p.height + 'px'; body.style.maxHeight = 'none'; }
  let lastH = p.height || 0;
  if (editable && 'ResizeObserver' in window) {
    new ResizeObserver(() => {
      if (!S.editing) return; // ne persiste qu'en mode édition
      const h = Math.round(body.clientHeight);
      if (h && Math.abs(h - lastH) > 8) { lastH = h; clearTimeout(body._t); body._t = setTimeout(() => patchPanel(p.id, { height: h }), 500); }
    }).observe(body);
  }
  // P7 : poignee de coin -> resize LIBRE (hauteur en px + largeur calee sur la grille, 1-4 col)
  if (editable) {
    const corner = document.createElement('div'); corner.className = 'rcorner editonly'; corner.title = 'Redimensionner (glisser)';
    card.appendChild(corner);
    corner.onmousedown = e => {
      e.preventDefault();
      const y0 = e.clientY, h0 = body.clientHeight, grid = card.parentElement;
      const slot = grid ? grid.clientWidth / 4 : 240; // un quart de la largeur du dashboard
      const left = card.getBoundingClientRect().left;
      const mv = ev => {
        body.style.maxHeight = 'none';
        body.style.height = Math.max(120, h0 + ev.clientY - y0) + 'px';
        const ncols = Math.max(1, Math.min(4, Math.round((ev.clientX - left) / slot)));
        card.style.flexBasis = tileBasis(ncols); card.dataset.cols = ncols;
      };
      const up = () => {
        document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up);
        const ncols = Number(card.dataset.cols) || (p.cols || 1);
        if (wsel) wsel.value = String(ncols);
        patchPanel(p.id, { cols: ncols }); // hauteur sauvee par le ResizeObserver
      };
      document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    };
  }
  let result = null;
  let pFrom = 0, pTo = 0;                                            // bornes de la dernière requête -> count_only
  const drawCount = { total: null, capped: false, fired: false };   // vrai total (count_only) pour une table cliente tronquée
  // PAGINATION GÉNÉRIQUE — extension du modèle Explore aux panneaux. Décision par FORME (viz + agrégation),
  // jamais par nom de champ. isAgg = pipe d'agrégation. Un panneau TABLE non-agrégé = LISTE DE LIGNES ->
  // pagination SERVEUR (scale 1M via /api/query + count_only, exactement comme Explore). Un panneau TABLE
  // agrégé = groupes déjà en mémoire -> pagination CLIENT du DOM (tableEl opts) + vrai total (count_only si tronqué).
  const pIsSoql = !!p.is_soql || /^\s*search\b/i.test(p.query || '') || (p.query || '').includes('|');
  const pIsAgg = pIsSoql && /\|\s*(stats|timechart|top|rare|eventstats)\b/i.test(p.query || '');
  // PROJECTION `| table`/`| fields` : le web reste en OFFSET pour ces panneaux. CE N'EST PLUS UNE
  // CONTRAINTE DU DAEMON — il sait désormais servir le curseur sur un pipeline projeté (il restitue la
  // clé de tri dans la projection puis la retire de la réponse, cf `keyset_projection_augment` côté
  // daemon). C'est un choix WEB, encore non pris : passer ces panneaux au curseur changerait l'ORDRE
  // affiché (l'offset les rend dans l'ordre physique SQLite, non spécifié ; le curseur impose le plus
  // récent d'abord). Tant que ce choix n'est pas fait, le web NE DOIT PAS envoyer `keyset:true` ici,
  // sinon il mélangerait deux ordres entre les pages d'une même navigation.
  const pIsProjected = pIsSoql && /\|\s*(table|fields)\b/i.test(p.query || '');
  const PANEL_PAGE = 50;
  // état pager SERVEUR PAR-PANNEAU (isolé des autres panneaux — plusieurs panneaux paginent indépendamment).
  // ① KEYSET (MIRROIR d'Explore `evLoad`, modèle Splunk) : un browse brut GXQL (`search` nu, from_soql) pagine par
  // CURSEUR en SÉQUENTIEL (Préc/Suiv = récup INTÉGRALE sans cap) MAIS garde le pager NUMÉROTÉ « 1..N » du COUNT ; un
  // clic sur un numéro de page NON atteint séquentiellement fait un SAUT OFFSET ponctuel (capé pour les pages très
  // lointaines = follow-up offset-dans-le-colonnaire). `cursors[i]` = curseur {ts,id} pour ATTEINDRE la page i (page 0
  // = null = sommet), capturé depuis `next_cursor` de la page i-1. Le SQL brut (admin, non-from_soql) reste en OFFSET.
  const panelKeyset = pIsSoql && !pIsProjected; // le daemon: do_keyset = keyset && from_soql && !projection
  const spg = { page: 0, pageSize: PANEL_PAGE, total: 0, shown: 0, totalCapped: false, countFired: false, realTotal: false, cols: null, rows: null,
    keyset: panelKeyset, cursors: [null] };
  // ne serveur-pagine QUE les listes de lignes (table + non-agrégé) ET seulement quand /api/query est autorisé
  // pour l'appelant (GXQL ouvert à tous ; SQL brut réservé admin) -> sinon repli sur la pagination CLIENT.
  const serverPaged = () => curViz === 'table' && !pIsAgg && (pIsSoql || socIsAdmin());
  function panelWindow() {
    const from = p.window_s > 0 ? Math.floor(Date.now() / 1000) - p.window_s : (currentFrom() || 0);
    const to = p.window_s > 0 ? 0 : currentTo();
    return { from, to };
  }
  function panelBad(m) { body.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + m })); }
  function renderServerPaged() {
    if (!spg.rows) return;
    const stats = result && result.stats;
    // `P10.5-i` — POSÉ AVANT LE RETOUR ANTICIPÉ. Ce chemin porte les LISTES DE LIGNES et ne passe jamais
    // par `draw()` : un aveu posé seulement là-bas ne l'atteindrait pas.
    if (!spg.rows.length && !spg.total) {
      body.replaceChildren(corpsSansLigne(stats, document.createTextNode('aucune donnée sur la fenêtre')));
      poserLesAveuxDuPanneau(body, stats, body.firstChild);   // la branche jumelle de `draw()` posait les deux ; celle-ci n'en posait aucun
      return;
    }
    body.replaceChildren();
    const go = pp => loadServerPage(pp);
    const top = makePager(spg, go); if (top) body.appendChild(top);
    body.appendChild(tableEl(spg.cols, spg.rows, p.query, p.drill || ''));
    const bot = makePager(spg, go); if (bot) body.appendChild(bot);
    poserLesAveuxDuPanneau(body, stats, body.firstChild);
  }
  // PAGE SERVEUR d'une liste de lignes : une seule page en mémoire (LIMIT/OFFSET) + total COUNT -> scale 1M.
  async function loadServerPage(page) {
    if (card._loadCtrl) { try { card._loadCtrl.abort(); } catch (e) {} }
    const ctrl = new AbortController(); card._loadCtrl = ctrl; panelInflight.add(ctrl);
    if (prog) prog.hidden = false; if (pstop) pstop.hidden = false;
    try {
      const { from, to } = panelWindow(); pFrom = from; pTo = to;
      // ① : la fenêtre a changé -> les curseurs {ts,id} capturés pour l'ancienne fenêtre sont obsolètes -> on
      // repart de la page 0 (curseur sommet) et on recompte le total. (L'offset, lui, reste valide sur toute fenêtre.)
      if (spg.keyset && spg.win && (spg.win.from !== from || spg.win.to !== to)) { page = 0; spg.cursors = [null]; spg.countFired = false; spg.realTotal = false; }
      spg.win = { from, to };
      const pg = Math.max(0, page);
      const reqBody = pIsSoql ? { soql: p.query } : { sql: p.query };
      reqBody.from = from; reqBody.to = to; reqBody.limit = spg.pageSize;
      if (spg.keyset) {
        // ① (mirroir evLoad) : curseur {ts,id} pour atteindre pg en SÉQUENTIEL ; page non atteinte (clic numéro loin /
        // dernière) -> SAUT OFFSET ponctuel. Le serveur renvoie next_cursor/has_more (séquentiel sans cap) OU total (saut).
        reqBody.keyset = true;
        const cur = spg.cursors[pg];
        const jumpOff = (!cur && pg > 0) ? pg * spg.pageSize : 0;
        // LE CURSEUR EST RÉÉMIS TEL QUEL, jamais reconstruit : il portait `{ ts: cur.ts, id: cur.id }`,
        // ce qui perd tout champ que le démon y a posé — dont l'espace d'identifiant du browse froid,
        // sans lequel la page suivante est REFUSÉE (cf. `aucun_module_web_ne_reconstruit_le_curseur_keyset`).
        if (cur) reqBody.cursor = cur;
        else if (jumpOff) reqBody.offset = jumpOff;
      } else {
        reqBody.offset = pg * spg.pageSize;
      }
      const r = await fetch('/api/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(reqBody), signal: ctrl.signal });
      const txt = await r.text().catch(() => '');
      const tg = transientGatewayMsg(r.status, r.ok ? '' : txt);
      if (tg) { panelBad(tg); return; }
      if (!txt) { panelBad('réponse vide (timeout proxy ou requête trop lourde ?)'); return; }
      let j;
      try { j = JSON.parse(txt); }
      catch { const tg2 = transientGatewayMsg(r.status, txt); if (tg2) { panelBad(tg2); return; } panelBad('réponse non-JSON (tronquée ? timeout ?)'); return; }
      if (!r.ok || j.error) { panelBad(j.error || r.status); return; }
      spg.page = Math.max(0, page); spg.cols = j.columns || []; spg.rows = j.rows || []; spg.shown = spg.rows.length;
      // ① KEYSET : mémorise le curseur de continuation (Suivant SÉQUENTIEL rapide, sans cap). Le total reste celui du
      // COUNT (pager NUMÉROTÉ commun) — un saut OFFSET renvoie `total`, une page séquentielle non (on garde l'ancien).
      if (spg.keyset) {
        // LE CURSEUR EST MÉMORISÉ **TEL QUE LE SERVEUR L'A RENDU**, jamais reconstruit. Il portait
        // `{ ts: nc.ts, id: nc.id }` — deux champs recopiés à la main — et cette recopie PERD tout
        // champ que le serveur y ajoute. Le browse froid colonnaire en ajoute un : l'espace
        // d'identifiant de la ligne qui a produit le curseur (une ligne froide n'a pas d'`id`, chaque
        // voie lui en fabrique un, et pas le même). Sans lui, le démon ne peut plus savoir quelle voie
        // sait relire ce nombre, et il REFUSE la page plutôt que d'en servir une qui commence ailleurs.
        // La validation reste la même ; c'est la VALEUR conservée qui change.
        const nc = j.next_cursor;
        spg.cursors[spg.page + 1] = (nc && typeof nc.ts === 'number' && typeof nc.id === 'number') ? nc : null;
      }
      if (!spg.realTotal && typeof j.total === 'number') { spg.total = j.total; spg.totalCapped = !!j.total_capped; }
      else if (!spg.realTotal && !spg.keyset) { spg.total = spg.rows.length; }
      result = { columns: spg.cols, rows: spg.rows, stats: j.stats };   // export du panneau = page courante
      renderServerPaged();
      // VRAI total NON plafonné (une seule fois) quand le COUNT serveur est plafonné OU keyset séquentiel (pas
      // de `total` inline) -> pager numéroté juste + saut-à-la-page possible. Réutilise le count_only NON plafonné.
      if (!spg.countFired && (spg.totalCapped || (spg.keyset && !spg.realTotal))) {
        spg.countFired = true;
        queryCount(p.query, pIsSoql, from, to).then(tot => { if (typeof tot === 'number' && tot >= 0) { spg.total = tot; spg.totalCapped = false; spg.realTotal = true; renderServerPaged(); } });
      }
    } catch (e) {
      if (e && e.name === 'AbortError') { flashStopped(prog); return; }
      body.textContent = 'erreur : ' + e.message;
    } finally {
      panelInflight.delete(ctrl); if (card._loadCtrl === ctrl) card._loadCtrl = null;
      if (prog && !prog.classList.contains('stopped')) prog.hidden = true;
      if (pstop) pstop.hidden = true; syncDashStop();
    }
  }
  function draw() {
    if (!result) return;
    // TABLE serveur-paginée (liste de lignes) : re-rendu de la page en mémoire, ou 1re page si pas encore chargée.
    if (serverPaged()) { if (spg.rows) renderServerPaged(); else loadServerPage(spg.page || 0); return; }
    // `P10.5-i` — LE CAS FONDATEUR EST ICI, ET IL SORT AVANT TOUT LE RESTE : une courbe vide sur une
    // fenêtre plus ancienne que l'horizon. L'aveu est donc posé AVANT ce retour, pas après.
    if (!result.rows.length) {
      body.replaceChildren(corpsSansLigne(result.stats, document.createTextNode('aucune donnée sur la fenêtre')));
      poserLesAveuxDuPanneau(body, result.stats, body.firstChild);
      return;
    }
    // TABLE (agrégation = groupes en mémoire ; OU liste de lignes SQL-brut vue par un viewer, non serveur-paginée) :
    // pagination CLIENT du DOM + vrai total = nb de lignes en mémoire, remplacé par un count_only NON plafonné si le
    // résultat a atteint le plafond run_query (aucune ligne/groupe caché en silence). Les autres viz (chart/stat) inchangées.
    if (curViz === 'table') {
      const total = drawCount.total != null ? drawCount.total : result.rows.length;
      body.replaceChildren(tableEl(result.columns, result.rows, p.query, p.drill || '', { pager: true, pageSize: PANEL_PAGE, total, totalCapped: drawCount.capped }));
      poserLesAveuxDuPanneau(body, result.stats, body.firstChild);
      if (!drawCount.fired && result.stats && result.stats.truncated) {
        drawCount.fired = true; drawCount.capped = true;
        queryCount(p.query, pIsSoql, pFrom, pTo).then(tot => { if (typeof tot === 'number' && tot >= 0) { drawCount.total = tot; drawCount.capped = false; draw(); } });
      }
      return;
    }
    // `P11.18-a` — LE RÉGLAGE DES AXES, remis au graphe par-dessus la règle positionnelle qu'il partage
    // avec toutes les représentations (mesurée le 2026-08-25 : 1re colonne = abscisse, dernière =
    // ordonnée). La clé de mémorisation est l'identité du PANNEAU, donc le réglage survit au
    // rechargement, au changement de fenêtre et au passage d'une représentation traçante à une autre.
    // Sans réglage mémorisé, `noeudsDeVizReglee` rend l'appel `vizElement` d'origine, inchangé — les
    // chemins TABLE ci-dessus n'y passent même pas. Le re-dessin est `draw` lui-même : le choix
    // s'applique sans repartir au démon (les lignes servies sont déjà là).
    body.replaceChildren(...noeudsDeVizReglee(curViz, result.columns, result.rows, p.query, p.drill || '', p.id, draw));
    poserLesAveuxDuPanneau(body, result.stats, body.firstChild);
  }
  // chargement NON bloquant -> carte rendue tout de suite, requetes EN PARALLELE (WAL).
  async function load() {
    if (serverPaged()) return loadServerPage(spg.page || 0);
    if (card._loadCtrl) { try { card._loadCtrl.abort(); } catch (e) {} }
    const ctrl = new AbortController(); card._loadCtrl = ctrl; panelInflight.add(ctrl);
    if (prog) prog.hidden = false;
    if (pstop) pstop.hidden = false;
    try {
      const from = p.window_s > 0 ? Math.floor(Date.now() / 1000) - p.window_s : (currentFrom() || 0);
      const to = p.window_s > 0 ? 0 : currentTo(); // un panneau a fenetre fixe ignore le zoom global
      pFrom = from; pTo = to;
      const r = await fetch(`/api/panels/${p.id}/data?from=${from}&to=${to}`, { signal: ctrl.signal });
      const txt = await r.text().catch(() => '');   // texte d'abord -> gère réponse vide/tronquée (timeout proxy)
      const bad = m => body.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + m }));
      // PANNE TRANSITOIRE DE PASSERELLE : (502/503/504 ou corps HTML « no available server » pendant
      // un rollout) -> message propre au lieu du corps brut Traefik.
      const tg = transientGatewayMsg(r.status, r.ok ? '' : txt);   // ok=200 -> corps vérifié plus bas (cas HTML servi en 200)
      if (tg) { bad(tg); return; }
      if (!txt) { bad('réponse vide (timeout proxy ou requête trop lourde ?)'); return; }
      let j;
      try { j = JSON.parse(txt); }
      catch {
        const tg2 = transientGatewayMsg(r.status, txt);   // corps HTML « no available server » servi en 200 -> transitoire
        if (tg2) { bad(tg2); return; }
        bad('réponse non-JSON (tronquée ? timeout ?) : ' + txt.slice(0, 120)); return;
      }
      if (!r.ok || j.error) { bad(j.error || r.status); return; }
      // FROID : 1er affichage d'un panneau jamais mesuré -> le daemon renvoie {warming:true} sans bloquer.
      // On montre un placeholder « chargement… » et on re-poll (3s) jusqu'aux vraies données -> plus de
      // « aucune donnée » à tort au retour sur Dashboards.
      if (j.warming === true) {
        // `P10.5-i` — CETTE BRANCHE JETTE LE CORPS ENTIER. Le démon publie pourtant l'horizon dans
        // l'objet synthétique : sans cette pose, un panneau en chauffe ne dirait rien de ce qu'il pourra
        // voir, alors même que c'est le premier écran que l'analyste regarde.
        body.replaceChildren(corpsSansLigne(j.stats, document.createTextNode('… chargement (mesure en cours)'), false));
        poserLesAveuxDuPanneau(body, j.stats, body.firstChild);
        clearTimeout(card._warmTimer);
        card._warmTimer = setTimeout(load, 3000);
        return;
      }
      clearTimeout(card._warmTimer); card._warmTimer = null;
      drawCount.total = null; drawCount.capped = false; drawCount.fired = false;   // ré-évalue la troncature à chaque (re)chargement
      result = { columns: j.columns, rows: j.rows, stats: j.stats }; draw();
    } catch (e) {
      if (e && e.name === 'AbortError') { flashStopped(prog); return; }   // STOP : feedback DISCRET via la barre (pas de texte)
      body.textContent = 'erreur : ' + e.message;
    } finally {
      panelInflight.delete(ctrl); if (card._loadCtrl === ctrl) card._loadCtrl = null;
      if (prog && !prog.classList.contains('stopped')) prog.hidden = true;   // ne pas couper le flash STOP en cours
      if (pstop) pstop.hidden = true; syncDashStop();
    }
  }
  // P5 : refresh par panneau ; un panneau a fenetre MANUELLE (window_s>0) ignore l'intervalle/refresh global
  // LAZY : on n'appelle PAS load() ici ; l'IntersectionObserver déclenche le 1er fetch quand la carte
  // devient visible (anti-rafale). Fallback sans IO -> chargement immédiat (comportement historique).
  card._panel = { window_s: p.window_s || 0, reload: load, loaded: false, visible: false };
  const obs = getPanelObserver();
  if (obs) obs.observe(card);
  else { card._panel.loaded = true; card._panel.visible = true; load(); }
  return card;
}
// Ajouter un dashboard a la vue : soit en RATTACHER un existant (select), soit en CREER un nouveau.
async function addDashboardFlow() {
  const view = $('#view') ? $('#view').value : '';
  let all = [];
  try { all = (await api('/dashboards')).dashboards || []; } catch (e) {}
  // dashboards editables pas deja dans cette vue (rattacher = deplacer ; le schema = 1 vue par dashboard)
  const attachable = view ? all.filter(d => d.editable !== false && String(d.view_id || '') !== String(view)) : [];
  const fields = [];
  if (attachable.length) fields.push({ name: 'existing', label: 'Rattacher un dashboard existant', type: 'select', value: '', options: [{ value: '', label: '+ Creer un nouveau dashboard' }, ...attachable.map(d => ({ value: String(d.id), label: d.name + (d.view_id ? ' (deplace depuis une autre vue)' : '') }))] });
  fields.push({ name: 'name', label: attachable.length ? 'Nom (si nouveau)' : 'Nom', placeholder: 'ex: Plume vue d ensemble', value: '' });
  fields.push({ name: 'visibility', label: 'Visibilité (si nouveau)', type: 'select', value: 'private', options: [{ value: 'private', label: 'Privé (vous + admin)' }, { value: 'shared', label: 'Partagé (groupe)' }] });
  const r = await modal({
    title: 'Ajouter un dashboard', okText: 'Ajouter', fields,
    validate: v => {
      if (v.existing) return null; // rattachement d'un existant
      if (!v.name || !v.name.trim()) return 'Donne un nom, ou choisis un dashboard existant.';
      if (all.some(d => d.name === v.name.trim())) return 'Un dashboard porte déjà ce nom.';
      return null;
    },
  });
  if (!r) return;
  if (r.existing) {
    await patchDash(Number(r.existing), { view_id: view ? Number(view) : null });
    toast('Dashboard rattaché à la vue', 'ok');
  } else {
    await apiSend('/dashboards', 'POST', { name: r.name.trim(), visibility: r.visibility, view_id: view ? Number(view) : null });
    toast('Dashboard créé', 'ok');
  }
  await loadDashboards(); await loadViews();
}

// ===================== #54 — INSTANTANÉ (snapshot partageable, lecture seule) =====================
// Capture les données rendues du dashboard via le chemin GXQL MASQUÉ côté serveur (au rôle de l'appelant) ->
// jamais un champ hors de sa portée. Renvoie {id, token}. On affiche un aperçu (rendu par les MÊMES
// vizElement) + un lien de partage read-only copiable (l'API renvoie le JSON figé au token).
async function captureSnapshot(d) {
  const from = currentFrom() || 0, to = currentTo();
  const j = await apiSend('/dashboard-snapshots', 'POST', { dashboard_id: d.id, from, to, name: d.name });
  if (!j || j.error) { toast('Instantané : ' + ((j && j.error) || 'échec'), 'bad'); return; }
  const url = location.origin + '/api/dashboard-snapshots/' + encodeURIComponent(j.token);
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal snapview';
  const close = () => { ov.classList.add('out'); setTimeout(() => ov.remove(), 160); };
  const h = document.createElement('h3'); h.textContent = 'Instantané : ' + d.name;
  const meta = document.createElement('div'); meta.className = 'muted'; meta.style.cssText = 'font-size:12px;margin:4px 0 8px';
  meta.textContent = 'Lecture seule, figé maintenant (données déjà masquées à votre rôle). Lien partageable :';
  const linkRow = document.createElement('div'); linkRow.className = 'rf-row';
  const inp = document.createElement('input'); inp.value = url; inp.readOnly = true; inp.style.flex = '1';
  // P11.4-h : LE geste de copie partagé remplace celui qui était écrit ici — même retour d'écran partout,
  // et l'échec du presse-papier se DIT au lieu de laisser croire que la valeur y est.
  const copy = boutonDeCopie(url, { titre: 'Copier le lien de partage de cet instantané' });
  linkRow.append(inp, copy);
  const prev = document.createElement('div'); prev.className = 'snapprev';
  const act = document.createElement('div'); act.className = 'modal-act';
  const cl = document.createElement('button'); cl.type = 'button'; cl.className = 'm-cancel'; cl.textContent = 'Fermer'; cl.onclick = close;
  act.appendChild(cl);
  box.append(h, meta, linkRow, prev, act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
  // aperçu : relit le snapshot par token (read-only) et rend chaque panneau avec les vizElement natifs.
  try {
    const snap = await api('/dashboard-snapshots/' + encodeURIComponent(j.token));
    const panels = (snap && snap.data && snap.data.panels) || [];
    prev.replaceChildren(...panels.map(p => {
      const card = document.createElement('div'); card.className = 'snapcard';
      const t = document.createElement('div'); t.className = 'snaptitle'; t.textContent = p.title || '';
      card.appendChild(t);
      if (p.error) { card.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'erreur : ' + p.error })); }
      // `P10.5-i` — L'INSTANTANÉ EST L'ARTEFACT QUI VOYAGE : partageable par jeton, relu des semaines
      // plus tard, hors de tout contexte de fenêtre. C'est le point de pose le plus nécessaire des quatre.
      else if (!p.rows || !p.rows.length) { card.appendChild(corpsSansLigne(p.stats, document.createTextNode('aucune donnée'))); }
      else card.appendChild(vizElement(p.viz || 'table', p.columns || [], p.rows || [], '', ''));
      poserLesAveuxDuPanneau(card, p.stats, null);
      return card;
    }));
  } catch (e) { prev.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aperçu indisponible' })); }
}

// ===================== #54 — DIAPORAMA (playlist / NOC wall-board) =====================
// Fait défiler les dashboards de la vue courante (S.dashList) un à un, sur un intervalle. Prev/next manuels.
// Autonome (aucune config serveur requise) ; la table `playlist` reste dispo pour persister des rotations nommées.
const PLAY = { on: false, idx: 0, timer: null };
function playTiles() { return [...($('#dashview') ? $('#dashview').querySelectorAll('.dashtile') : [])]; }
function playShow(i) {
  const tiles = playTiles(); if (!tiles.length) { playStop(); return; }
  PLAY.idx = ((i % tiles.length) + tiles.length) % tiles.length;
  tiles.forEach((t, k) => { t.style.display = k === PLAY.idx ? '' : 'none'; });
  const tile = tiles[PLAY.idx]; if (tile && tile._panel) {} // (le lazy-load des panneaux se déclenche à l'affichage)
  const pos = $('#dash-playpos'); if (pos) pos.textContent = (PLAY.idx + 1) + '/' + tiles.length;
  tiles[PLAY.idx].scrollIntoView({ block: 'nearest' });
}
function playTick() {
  const step = () => { playShow(PLAY.idx + 1); schedule(); };
  const schedule = () => { const s = Math.max(3, Math.min(3600, Number(($('#dash-playint') && $('#dash-playint').value) || 30))); PLAY.timer = setTimeout(step, s * 1000); };
  clearTimeout(PLAY.timer); schedule();
}
function playStart() {
  if (!playTiles().length) { toast('Aucun dashboard à faire défiler dans cette vue.', 'bad'); return; }
  PLAY.on = true; PLAY.idx = 0;
  const bar = $('#dash-playbar'); if (bar) bar.hidden = false;
  const btn = $('#dash-play'); if (btn) btn.classList.add('on');
  playShow(0); playTick();
}
function playStop() {
  PLAY.on = false; clearTimeout(PLAY.timer); PLAY.timer = null;
  playTiles().forEach(t => { t.style.display = ''; });
  const bar = $('#dash-playbar'); if (bar) bar.hidden = true;
  const btn = $('#dash-play'); if (btn) btn.classList.remove('on');
}
// "Sauver comme panneau" depuis Explore : choisit le dashboard cible dans la vue courante
// P11.9-a : « Panneau » a quitté la barre de recherche — un panneau se crée depuis son tableau de bord,
// pré-rempli avec la requête courante (voir les deux « Ajouter un panneau »).

// --- vues (ensembles de dashboards) ---
async function loadViews() {
  const sel = $('#view'); if (!sel) return;
  try {
    const { views, role, me } = await api('/views');
    S.viewList = views || [];
    if (role) { applyRoleClass(role); S.viewsRole = role; }
    if (me != null) S.viewsMe = me;   // #17 team — identité pour la garde de partage (bascule scope)
    const cur = sel.value;
    sel.replaceChildren();
    const all = document.createElement('option'); all.value = ''; all.textContent = '— Sans filtre de vue —'; sel.appendChild(all);
    // #17 team — le label distingue explicitement une vue PARTAGÉE (équipe) d'une vue privée -> l'équipe
    // voit d'un coup d'œil quels regroupements de dashboards sont communs.
    (views || []).forEach(v => { const o = document.createElement('option'); o.value = v.id; o.textContent = `${v.name}${v.visibility === 'shared' ? ' (équipe)' : ' (privé)'} (${v.dashboards})`; sel.appendChild(o); });
    if (cur) sel.value = cur;
  } catch (e) {}
  updateViewShareBtn();
}
// #17 team — SAVED-VIEW SHARING : bascule du scope d'une vue partagée<->privée. Backend prêt (view_update
// accepte {visibility} ; views_list renvoie owner/visibility/me/role). Garde MIROIR de view_update (admin,
// propriétaire, ou vue sans owner legacy) ; le daemon refait foi (défense en profondeur).
function viewCanShare(v) { return !!v && (S.viewsRole === 'admin' || !v.owner || v.owner === S.viewsMe); }
function updateViewShareBtn() {
  const btn = $('#view-share'), sel = $('#view'); if (!btn || !sel) return;
  const v = S.viewList.find(x => String(x.id) === String(sel.value));
  if (!v || !viewCanShare(v)) { btn.hidden = true; return; }
  const shared = v.visibility === 'shared';
  btn.hidden = false; btn.innerHTML = ic('users'); btn.classList.toggle('on', shared);
  btn.setAttribute('aria-pressed', shared ? 'true' : 'false');
  const owner = v.owner ? ' (propriétaire : ' + v.owner + ')' : '';
  btn.title = shared ? `Vue partagée avec l'équipe${owner} — cliquer pour la rendre privée`
                     : `Vue privée${owner} — cliquer pour la partager avec l'équipe`;
}

function initDashboards() {
  if ($('#dash-new')) $('#dash-new').addEventListener('click', addDashboardFlow);
  if ($('#dash-refresh')) $('#dash-refresh').addEventListener('click', refreshDashboards);
  if ($('#dash-stop')) $('#dash-stop').addEventListener('click', stopDashboards);
  if ($('#dash-edit')) $('#dash-edit').addEventListener('click', () => {
    S.editing = !S.editing;
    const v = $('#dashview'); if (v) v.classList.toggle('editing', S.editing);
    $('#dash-edit').classList.toggle('on', S.editing);
  });
  if ($('#dash-play')) $('#dash-play').addEventListener('click', () => { PLAY.on ? playStop() : playStart(); });
  if ($('#dash-playstop')) $('#dash-playstop').addEventListener('click', playStop);
  if ($('#dash-prev')) $('#dash-prev').addEventListener('click', () => { if (PLAY.on) { playShow(PLAY.idx - 1); playTick(); } });
  if ($('#dash-next')) $('#dash-next').addEventListener('click', () => { if (PLAY.on) { playShow(PLAY.idx + 1); playTick(); } });
  if ($('#dash-playint')) $('#dash-playint').addEventListener('change', () => { if (PLAY.on) playTick(); });
  if ($('#view')) { $('#view').addEventListener('change', loadDashboards); $('#view').addEventListener('change', updateViewShareBtn); }
  if ($('#view-share')) $('#view-share').addEventListener('click', async () => {
    const sel = $('#view'); const id = sel && sel.value;
    const v = S.viewList.find(x => String(x.id) === String(id));
    if (!v) { toast('Sélectionne une vue à partager (pas « — Sans filtre de vue — »).', 'bad'); return; }
    if (!viewCanShare(v)) { toast('Seuls le propriétaire ou un admin peuvent changer le partage.', 'bad'); return; }
    const next = v.visibility === 'shared' ? 'private' : 'shared';
    // `P11.13-b` — CE GESTE CHANGE QUI PEUT LIRE, ET IL PARTAIT SANS RIEN DEMANDER. Un clic sur une
    // icône basculait une vue privée en vue d'équipe (et l'inverse) : aucune conséquence n'était
    // montrée avant l'écriture, alors que le voisin destructif du même bandeau, lui, confirmait.
    // MESURÉ le 2026-08-26 : `check_sensitive_routes_are_confirmed.py` déclarait pourtant cet appel
    // « confirmé » — non par une confirmation à lui, mais parce que son ancêtre `initDashboards`
    // CONTIENT le `confirmModal(` du bouton « supprimer la vue », dont la fonction ne contient pas cet
    // appel. Une confirmation de VOISIN. La garde regarde plus large qu'elle ne le peut ; ce qui se
    // corrige ici est le CÔTÉ CONSOLE, celui qui manquait pour de bon.
    // LA CONSÉQUENCE EST NOMMÉE, ET ELLE EST LUE DANS LE DÉMON, pas devinée (2026-08-26) : `views_list`
    // sert une vue à tous dès qu'elle est `shared`, tandis que `dash_list` filtre chaque tableau de bord
    // sur SA PROPRE visibilité. Partager la vue ne partage donc pas les tableaux de bord privés qu'elle
    // porte, et la phrase le dit plutôt que de promettre plus que ce qui se produit.
    const versPartage = next === 'shared';
    const geste = LANG === 'en'
      ? (versPartage ? 'Share this view with the team?' : 'Make this view private?')
      : (versPartage ? 'Partager cette vue avec l’équipe ?' : 'Rendre cette vue privée ?');
    const consequence = LANG === 'en'
      ? (versPartage
        ? 'The view “' + v.name + '” will show up in everyone’s list, and the SHARED dashboards it carries become reachable from it. Private dashboards stay private.'
        : 'The view “' + v.name + '” disappears from everyone else’s list — only you and an administrator keep it. The dashboards it carries do not change visibility.')
      : (versPartage
        ? 'La vue « ' + v.name + ' » apparaîtra dans la liste de tout le monde, et les tableaux de bord PARTAGÉS qu’elle porte se lisent alors depuis elle. Les tableaux de bord privés restent privés.'
        : 'La vue « ' + v.name + ' » disparaît de la liste des autres — seuls vous et un administrateur la gardez. Les tableaux de bord qu’elle porte ne changent pas de visibilité.');
    if (!await confirmWithConsequence(geste, consequence)) return;
    try { await apiSend('/views/' + id, 'POST', { visibility: next }); }
    catch (e) { toast('Changement de partage refusé (' + (e && e.message ? e.message : e) + ')', 'bad'); return; }
    await loadViews(); sel.value = id; updateViewShareBtn();
    toast(next === 'shared' ? 'Vue partagée avec l\'équipe' : 'Vue rendue privée', 'ok');
  });
  if ($('#view-new')) $('#view-new').addEventListener('click', async () => {
    const r = await modal({
      title: 'Nouvelle vue', okText: 'Créer', fields: [
        { name: 'name', label: 'Nom', required: true, placeholder: 'ex: Production' },
        { name: 'visibility', label: 'Visibilité', type: 'select', value: 'private', options: [{ value: 'private', label: 'Privé (vous + admin)' }, { value: 'shared', label: 'Partagé (groupe)' }] },
      ], validate: v => S.viewList.some(x => x.name === v.name.trim()) ? 'Une vue porte déjà ce nom.' : null,
    });
    if (!r) return;
    const cr = await apiSend('/views', 'POST', { name: r.name.trim(), visibility: r.visibility });
    await loadViews(); if (cr.id) $('#view').value = cr.id; loadDashboards(); toast('Vue créée', 'ok');
  });
  if ($('#view-del')) $('#view-del').addEventListener('click', async () => {
    const sel = $('#view'); if (!sel.value) { toast('Sélectionne une vue à supprimer.', 'bad'); return; }
    if (!await confirmModal('Supprimer cette vue ? Les dashboards sont conservés (détachés de la vue).', { danger: true })) return;
    await apiSend('/views/' + sel.value, 'DELETE');
    sel.value = ''; await loadViews(); loadDashboards();
  });
  if ($('#view-rename')) {
    $('#view-rename').innerHTML = ic('pencil');
    $('#view-rename').addEventListener('click', async () => {
      const sel = $('#view'); const id = sel && sel.value;
      if (!id) { toast('Sélectionne une vue à renommer (pas « — Sans filtre de vue — »).', 'bad'); return; }
      const v = S.viewList.find(x => String(x.id) === String(id));
      const r = await modal({ title: 'Renommer la vue', okText: 'Enregistrer', fields: [{ name: 'name', label: 'Nom', required: true, value: v ? v.name : '' }], validate: x => S.viewList.some(y => String(y.id) !== String(id) && y.name === x.name.trim()) ? 'Une vue porte déjà ce nom.' : null });
      if (!r) return;
      await apiSend('/views/' + id, 'POST', { name: r.name.trim() });
      await loadViews(); $('#view').value = id; toast('Vue renommée', 'ok');
    });
  }
  loadViews();
  loadDashboards();
}

// `corpsSansLigne` est exporté POUR LE HARNAIS, comme `renderDashboard` : la règle qu'il porte — un corps
// sans ligne n'établit une absence que si le lecteur sait jusqu'où le panneau a regardé — se prouve en
// l'EXÉCUTANT, pas en relisant le module.
export { corpsSansLigne, initDashboards, loadDashboard, loadDashboards, refreshPanels, renderDashboard };

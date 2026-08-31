// savedqueries.js — MES MODÈLES de requête (persistants, per-user) + HISTORIQUE RÉCENT de la barre Explore (#sql).
// 100 % natif (aucun LLM/modèle, aucun appel externe).
//
//  1) MES MODÈLES — adossés au serveur (GET/POST/PUT/DELETE /api/saved-queries, table `saved_query`,
//     OWNER-scoped strict : chaque utilisateur ne voit/charge/édite/supprime QUE les siens ; l'isolation est
//     imposée SERVEUR, cf. handlers/saved_queries.rs). « Enregistrer » capture le texte de la barre (draft
//     autorisé, jamais compilé au save) et le range parmi les MODÈLES ; le palette « Modèles »
//     (soql_complete.js) les liste à côté des modèles LIVRÉS, avec modification et suppression.
//     P11.9-a — MESURÉ le 2026-08-22 : la barre portait QUATRE affordances (Modèles / Enregistrer /
//     Sauvegardées / Récentes) pour DEUX stockages (la bibliothèque livrée, lecture seule, et cette table
//     per-user). « Sauvegardées » n'était que l'autre nom des requêtes enregistrées : elle DISPARAÎT, son
//     contenu est le même stockage (aucune migration de données — la table `saved_query` EST « mes
//     modèles »), et le bouton `#qsaved`, s'il est encore dans le gabarit, est caché ici.
//     Charger REMPLIT la barre — SANS l'exécuter (l'analyste relit puis exécute).
//
//  2) HISTORIQUE RÉCENT (client-only, localStorage, par navigateur) — les ~20 dernières requêtes DISTINCTES
//     exécutées, dédupliquées, plus-récente-d'abord, effaçables. Aucun stockage serveur, aucun endpoint,
//     aucune donnée sensible au-delà du navigateur local.
//
// SÉCURITÉ : l'endpoint saved-queries est owner-scoped côté serveur (clé = identité authentifiée ; le client
// n'envoie JAMAIS d'identifiant d'utilisateur) -> pas d'IDOR/énumération. Le texte GXQL stocké est INERTE :
// il n'est compilé/masqué/autorisé qu'au run, par le chemin gardé /api/query (comme une requête tapée à la main).
import { $, api, apiSend, toast, modal, confirmModal, bornerLePopoverSousSonAncre } from './core.js';
import { ecrireSansDireLeRefus } from './state.js';

// ============================ 2) HISTORIQUE RÉCENT (localStorage) ============================
const RECENT_KEY = 'plume_recent_queries';
const RECENT_MAX = 20;

function readRecent() {
  try { const a = JSON.parse(localStorage.getItem(RECENT_KEY)); return Array.isArray(a) ? a.filter(s => typeof s === 'string') : []; }
  catch (e) { return []; }
}
// `P4.13-d` — NAVIGATION : AUCUN CHOIX N'EST FAIT ICI, ET L'AVIS PARTIRAIT À CHAQUE REQUÊTE. `writeRecent`
// est appelé par `recordRecentQuery`, lui-même appelé à CHAQUE exécution de requête : c'est un effet de
// bord automatique, pas un geste que l'exploitant pose en attendant qu'il tienne. Dire la perte ici
// avertirait à chaque exécution — exactement l'avis inutile qui use celui qui compte. Le silence est
// DÉCLARÉ par la porte franchie, et non plus laissé à une capture au corps vide.
function writeRecent(a) { ecrireSansDireLeRefus(RECENT_KEY, JSON.stringify(a)); }

// recordRecentQuery(sql) — appelé à CHAQUE exécution (depuis qHistPush de viz.js). Dédup (retire toute
// occurrence identique) + place en tête (plus-récent-d'abord) + plafond 20. Fire-and-forget.
export function recordRecentQuery(sql) {
  sql = (sql || '').trim();
  if (!sql) return;
  let a = readRecent().filter(s => s !== sql);   // dédup : une re-exécution remonte, ne duplique pas
  a.unshift(sql);                                // plus-récent-d'abord
  if (a.length > RECENT_MAX) a = a.slice(0, RECENT_MAX);
  writeRecent(a);
}

// ============================ CHARGEMENT DANS LA BARRE (jamais d'auto-run) ====================
export function loadIntoBar(sql) {
  const el = $('#sql');
  if (!el) return;
  el.value = sql;
  el.focus();
  // notifie les hints/complétion (soql_complete écoute `input`) ; N'EXÉCUTE PAS (pas de runQuery).
  try { el.dispatchEvent(new Event('input', { bubbles: true })); } catch (e) {}
}

// ============================ DROPDOWN générique (thème-aware, réutilise .minimenu) ===========
let _closeDrop = null;
function closeDrop() { if (_closeDrop) { const f = _closeDrop; _closeDrop = null; f(); } }

// openDrop(anchor, build) — ouvre un panneau ancré sous `anchor`. `build(panel, close)` remplit le contenu.
// Ferme au clic extérieur / Échap / défilement de la PAGE. Un seul ouvert à la fois.
//
// `P11.22-b` — LA BORNE NE BORNAIT PAS CE QU'ON CROYAIT, MESURÉ LE 2026-08-30. Ce panneau tenait sa hauteur
// de `.sq-menu{max-height:60vh}` et sa position d'un `top = r.bottom + 4` posé à la main. Or une hauteur
// exprimée en fraction de FENÊTRE limite la HAUTEUR d'une boîte `position:fixed`, JAMAIS sa POSITION : à
// 60 vh d'une fenêtre de 800 px la boîte fait 480 px, donc elle sortait de l'écran dès que le bas de l'ancre
// passait 316 px — 84 px dehors pour une ancre à 400 px, 396 px dehors pour une ancre à 712 px. Sans erreur
// ET SANS BARRE DE DÉFILEMENT : le contenu tenait sous le plafond, rien ne débordait DE LA BOÎTE, c'est la
// boîte qui débordait de l'écran. Ce n'était pas théorique — le bas de `#qrecent` siège vers 294 px au repos
// en 1280×800 (`#sql` fait 80 px et les commandes de `.qbar` passent à la ligne), soit 22 px de marge ; la
// même page en 1366×768 (fenêtre utile ~640 px, donc seuil 252 px) est DÉJÀ dehors de 41 px, et `#sql` est
// `resize:vertical` — agrandir l'éditeur de 220 px suffit à sortir la boîte sur n'importe quel écran.
// La hauteur est donc posée en pixels RÉELS sous l'ancre par le geste commun de `core.js`, qui bascule
// au-dessus de l'ancre quand l'espace manque dessous. Il n'est PAS réécrit ici : il est importé.
function openDrop(anchor, build) {
  closeDrop();
  const panel = document.createElement('div');
  panel.className = 'minimenu sq-menu noprint';
  build(panel, closeDrop);
  document.body.appendChild(panel);
  const r = anchor.getBoundingClientRect();
  panel.style.position = 'fixed';
  // La barre de défilement est rendue VISIBLE plutôt que laissée en surimpression : c'est ELLE qui dit
  // qu'il reste des requêtes sous le pli. `overscroll-behavior:contain` retient la molette au bout de la
  // liste — sans lui elle passerait à la page, et un défilement de page ferme le menu (à raison : il est
  // ancré en coordonnées de fenêtre). Posé ICI et non dans la feuille de style, qui n'appartient pas à ce
  // lot ; `.sq-menu` mérite en plus les règles `::-webkit-scrollbar` de `.colsmenu`, qu'un style en ligne
  // ne peut pas porter — sans elles, Safari garde sa barre escamotable et seul le pied collant parle.
  panel.style.overscrollBehavior = 'contain';
  panel.style.scrollbarWidth = 'thin';
  panel.style.scrollbarColor = 'var(--bd) transparent';
  bornerLePopoverSousSonAncre(panel, r);
  // `offsetWidth` est lu APRÈS le bornage : une hauteur bornée peut faire apparaître la barre de
  // défilement, donc élargir la boîte — le lire avant la déborderait du bord droit de la largeur de barre.
  panel.style.left = Math.max(6, Math.min(r.left, window.innerWidth - panel.offsetWidth - 6)) + 'px';
  const onDoc = e => { if (!panel.contains(e.target) && e.target !== anchor) closeDrop(); };
  const onKey = e => { if (e.key === 'Escape') closeDrop(); };
  // Le panneau est ancré en coordonnées de FENÊTRE : un défilement de PAGE le laisserait collé à une
  // position périmée, sous une ancre qui a bougé. On le ferme donc — en phase de CAPTURE, seule façon de
  // voir le défilement d'un conteneur imbriqué. Mais le document reçoit ALORS le défilement de la liste
  // elle-même : sans la garde `panel.contains`, elle se fermerait au premier cran de molette, ce qui se
  // lit exactement « elle ne défile pas ». La garde ne doit pas non plus aller jusqu'à ne PLUS fermer.
  const onScroll = e => { if (!panel.contains(e.target)) closeDrop(); };
  setTimeout(() => { document.addEventListener('mousedown', onDoc); document.addEventListener('keydown', onKey); document.addEventListener('scroll', onScroll, true); }, 0);
  _closeDrop = () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); document.removeEventListener('scroll', onScroll, true); panel.remove(); };
}

function emptyRow(text) {
  const d = document.createElement('div'); d.className = 'sq-empty'; d.textContent = text; return d;
}

// ============================ 1) MES MODÈLES (serveur, owner-scoped) ==========================
// null = chargement échoué (déjà signalé par un toast) ; [] = aucun modèle personnel.
export async function fetchSaved() {
  try { const d = await api('/saved-queries'); return (d && Array.isArray(d.queries)) ? d.queries : []; }
  catch (e) { toast('Chargement de mes modèles échoué : ' + e.message, 'err'); return null; }
}

// Enregistrer un texte sous un nom parmi MES MODÈLES. Draft autorisé (texte vide accepté par le serveur).
// `preset` = {name, soql} pour pré-remplir (copie d'un modèle livré) ; sans preset, le texte de la barre.
export async function saveAsTemplate(preset) {
  const sql = preset && typeof preset.soql === 'string' ? preset.soql : (($('#sql') && $('#sql').value) || '').trim();
  const vals = await modal({
    title: 'Enregistrer dans mes modèles',
    okText: 'Enregistrer',
    fields: [
      { name: 'name', label: 'Nom du modèle', required: true, value: (preset && preset.name) || '', placeholder: 'ex : erreurs 4xx — 24 h' },
      { name: 'soql', label: 'Requête (GXQL)', type: 'textarea', value: sql, placeholder: 'search source=… | stats count by …' },
    ],
  });
  if (!vals) return null;
  try {
    const r = await apiSend('/saved-queries', 'POST', { name: vals.name, soql: vals.soql || '' });
    toast('Modèle enregistré — retrouvez-le sous « Modèles »', 'ok');
    return r || { name: vals.name, soql: vals.soql || '' };
  } catch (e) {
    toast('Enregistrement échoué : ' + e.message, 'err');
    return null;
  }
}
export function saveCurrent() { return saveAsTemplate(null); }

// Renommer / modifier un modèle personnel (PUT owner-scoped, IDOR-sûr côté serveur).
export async function editSaved(q, onDone) {
  const vals = await modal({
    title: 'Modifier le modèle',
    okText: 'Enregistrer',
    fields: [
      { name: 'name', label: 'Nom du modèle', required: true, value: q.name },
      { name: 'soql', label: 'Requête (GXQL)', type: 'textarea', value: q.soql || '' },
    ],
  });
  if (!vals) return;
  try {
    await apiSend('/saved-queries/' + encodeURIComponent(q.id), 'PUT', { name: vals.name, soql: vals.soql || '' });
    toast('Modèle mis à jour', 'ok');
    if (onDone) onDone();
  } catch (e) {
    toast('Mise à jour échouée : ' + e.message, 'err');
  }
}

export async function deleteSaved(q, onDone) {
  if (!(await confirmModal(`Supprimer le modèle « ${q.name} » ?`, { title: 'Supprimer', okText: 'Supprimer' }))) return;
  try {
    await apiSend('/saved-queries/' + encodeURIComponent(q.id), 'DELETE');
    toast('Modèle supprimé', 'ok');
    if (onDone) onDone();
  } catch (e) {
    toast('Suppression échouée : ' + e.message, 'err');
  }
}

// Ouvre le dropdown de l'historique récent (localStorage) : chaque ligne charge la requête ; bouton « Effacer ».
function openRecentMenu(anchor) {
  const list = readRecent();
  openDrop(anchor, (panel, close) => {
    if (!list.length) { panel.appendChild(emptyRow('Aucune requête récente')); return; }
    list.forEach(sql => {
      const b = document.createElement('button'); b.type = 'button'; b.className = 'minimenu-item sq-recent';
      b.textContent = sql.length > 80 ? sql.slice(0, 80) + '…' : sql; b.title = sql;
      b.onclick = () => { close(); loadIntoBar(sql); };
      panel.appendChild(b);
    });
    // `P11.22-b` — LA PURGE NE DÉFILE PAS AVEC CE QU'ELLE VIDE. « Effacer l'historique » est la DERNIÈRE
    // ligne d'une liste qui CROÎT avec l'usage : au plafond de 20 entrées le contenu fait ~670 px, borné
    // ici à l'espace réel sous l'ancre (~480 px en 800 px de fenêtre, ~330 en 640). Elle était donc la
    // PREMIÈRE à passer sous le pli, et l'exploitant dont l'historique débordait perdait exactement le
    // geste qui l'aurait vidé. Collée au bas de la zone défilante (`-4px` = la marge intérieure de
    // `.minimenu`, qu'elle recouvre), elle reste offerte quel que soit le rang atteint — et sa présence
    // permanente AU-DESSUS des lignes qui glissent DIT que la liste continue, sans un mot de plus à
    // traduire. Le fond opaque est porté par le PIED et non par le bouton : `.minimenu-item:hover` garde
    // ainsi sa prise, qu'un `background` en ligne sur le bouton lui aurait retirée.
    const pied = document.createElement('div');
    pied.style.position = 'sticky'; pied.style.bottom = '-4px'; pied.style.background = 'var(--card)';
    pied.style.display = 'flex'; pied.style.flexDirection = 'column'; pied.style.paddingBottom = '4px';
    const sep = document.createElement('div'); sep.className = 'sq-sep'; pied.appendChild(sep);
    const clr = document.createElement('button'); clr.type = 'button'; clr.className = 'minimenu-item sq-clear'; clr.textContent = 'Effacer l’historique';
    clr.onclick = () => { close(); writeRecent([]); toast('Historique effacé', 'ok'); };
    pied.appendChild(clr);
    panel.appendChild(pied);
  });
}

// initSavedQueries() — câble la barre Explore : « Enregistrer » (-> mes modèles) et « Récentes ».
// « Sauvegardées » (#qsaved) n'a plus de contenu propre : caché tant que le gabarit le porte encore.
// Idempotent-safe : appelé une fois au boot. Silencieux si les boutons n'existent pas.
export function initSavedQueries() {
  const save = $('#qsave'), saved = $('#qsaved'), recent = $('#qrecent');
  if (save) save.addEventListener('click', () => saveCurrent());
  if (saved) saved.hidden = true;
  if (recent) recent.addEventListener('click', () => openRecentMenu(recent));
}

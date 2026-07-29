// savedqueries.js — outillage analyste de la barre Explore (#sql). Deux surfaces, 100 % natives (aucun
// LLM/modèle, aucun appel externe) :
//
//  1) REQUÊTES SAUVEGARDÉES (persistantes, per-user, tenant-scoped) — adossées au serveur
//     (GET/POST/PUT/DELETE /api/saved-queries, OWNER-scoped strict : chaque utilisateur ne voit/charge/édite/
//     supprime QUE ses propres requêtes ; l'isolation est imposée SERVEUR, cf. handlers/saved_queries.rs).
//     Enregistrer capture le texte de la barre (draft autorisé, jamais compilé au save). Charger REMPLIT la
//     barre — SANS l'exécuter (l'analyste relit puis exécute, cohérent avec le modèle advisory complétion/valide).
//
//  2) HISTORIQUE RÉCENT (client-only, localStorage, par navigateur) — les ~20 dernières requêtes DISTINCTES
//     exécutées, dédupliquées, plus-récente-d'abord, effaçables. Aucun stockage serveur, aucun endpoint,
//     aucune donnée sensible au-delà du navigateur local.
//
// SÉCURITÉ : l'endpoint saved-queries est owner-scoped côté serveur (clé = identité authentifiée ; le client
// n'envoie JAMAIS d'identifiant d'utilisateur) -> pas d'IDOR/énumération. Le texte GXQL stocké est INERTE :
// il n'est compilé/masqué/autorisé qu'au run, par le chemin gardé /api/query (comme une requête tapée à la main).
import { $, api, apiSend, toast, modal, confirmModal, esc } from './core.js';

// ============================ 2) HISTORIQUE RÉCENT (localStorage) ============================
const RECENT_KEY = 'plume_recent_queries';
const RECENT_MAX = 20;

function readRecent() {
  try { const a = JSON.parse(localStorage.getItem(RECENT_KEY)); return Array.isArray(a) ? a.filter(s => typeof s === 'string') : []; }
  catch (e) { return []; }
}
function writeRecent(a) { try { localStorage.setItem(RECENT_KEY, JSON.stringify(a)); } catch (e) {} }

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
function loadIntoBar(sql) {
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
// Ferme au clic extérieur / Échap. Un seul ouvert à la fois.
function openDrop(anchor, build) {
  closeDrop();
  const panel = document.createElement('div');
  panel.className = 'minimenu sq-menu noprint';
  build(panel, closeDrop);
  document.body.appendChild(panel);
  const r = anchor.getBoundingClientRect();
  panel.style.position = 'fixed';
  panel.style.top = (r.bottom + 4) + 'px';
  panel.style.left = Math.max(6, Math.min(r.left, window.innerWidth - panel.offsetWidth - 6)) + 'px';
  const onDoc = e => { if (!panel.contains(e.target) && e.target !== anchor) closeDrop(); };
  const onKey = e => { if (e.key === 'Escape') closeDrop(); };
  setTimeout(() => { document.addEventListener('mousedown', onDoc); document.addEventListener('keydown', onKey); }, 0);
  _closeDrop = () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); panel.remove(); };
}

function emptyRow(text) {
  const d = document.createElement('div'); d.className = 'sq-empty'; d.textContent = text; return d;
}

// ============================ 1) REQUÊTES SAUVEGARDÉES (serveur, owner-scoped) ================
async function fetchSaved() {
  try { const d = await api('/saved-queries'); return (d && Array.isArray(d.queries)) ? d.queries : []; }
  catch (e) { toast('Chargement des requêtes sauvegardées échoué : ' + e.message, 'err'); return null; }
}

// Enregistrer le texte COURANT de la barre sous un nom. Draft autorisé (texte vide accepté par le serveur).
async function saveCurrent() {
  const sql = (($('#sql') && $('#sql').value) || '').trim();
  const vals = await modal({
    title: 'Enregistrer la requête',
    okText: 'Enregistrer',
    fields: [
      { name: 'name', label: 'Nom', required: true, placeholder: 'ex : erreurs 4xx — 24 h' },
      { name: 'soql', label: 'Requête (GXQL)', type: 'textarea', value: sql, placeholder: 'search source=… | stats count by …' },
    ],
  });
  if (!vals) return;
  try {
    await apiSend('/saved-queries', 'POST', { name: vals.name, soql: vals.soql || '' });
    toast('Requête enregistrée', 'ok');
  } catch (e) {
    toast('Enregistrement échoué : ' + e.message, 'err');
  }
}

// Renommer / modifier une requête sauvegardée existante (PUT owner-scoped, IDOR-sûr côté serveur).
async function editSaved(q, onDone) {
  const vals = await modal({
    title: 'Modifier la requête',
    okText: 'Enregistrer',
    fields: [
      { name: 'name', label: 'Nom', required: true, value: q.name },
      { name: 'soql', label: 'Requête (GXQL)', type: 'textarea', value: q.soql || '' },
    ],
  });
  if (!vals) return;
  try {
    await apiSend('/saved-queries/' + encodeURIComponent(q.id), 'PUT', { name: vals.name, soql: vals.soql || '' });
    toast('Requête mise à jour', 'ok');
    if (onDone) onDone();
  } catch (e) {
    toast('Mise à jour échouée : ' + e.message, 'err');
  }
}

async function deleteSaved(q, onDone) {
  if (!(await confirmModal(`Supprimer la requête « ${q.name} » ?`, { title: 'Supprimer', okText: 'Supprimer' }))) return;
  try {
    await apiSend('/saved-queries/' + encodeURIComponent(q.id), 'DELETE');
    toast('Requête supprimée', 'ok');
    if (onDone) onDone();
  } catch (e) {
    toast('Suppression échouée : ' + e.message, 'err');
  }
}

// Ouvre le dropdown des requêtes sauvegardées : chaque ligne = charger (clic sur le nom) + ✎ modifier + × supprimer.
async function openSavedMenu(anchor) {
  const rows = await fetchSaved();
  if (rows === null) return;   // erreur déjà signalée
  const render = list => {
    openDrop(anchor, (panel, close) => {
      if (!list.length) { panel.appendChild(emptyRow('Aucune requête sauvegardée')); return; }
      list.forEach(q => {
        const row = document.createElement('div'); row.className = 'sq-row';
        const load = document.createElement('button'); load.type = 'button'; load.className = 'minimenu-item sq-load';
        load.textContent = q.name; load.title = q.soql || '(vide)';
        load.onclick = () => { close(); loadIntoBar(q.soql || ''); };
        const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'sq-icon'; edit.title = 'Modifier'; edit.textContent = '✎';
        edit.onclick = e => { e.stopPropagation(); close(); editSaved(q, () => {}); };
        const del = document.createElement('button'); del.type = 'button'; del.className = 'sq-icon sq-del'; del.title = 'Supprimer'; del.textContent = '×';
        del.onclick = e => { e.stopPropagation(); close(); deleteSaved(q, () => {}); };
        row.append(load, edit, del);
        panel.appendChild(row);
      });
    });
  };
  render(rows);
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
    const sep = document.createElement('div'); sep.className = 'sq-sep'; panel.appendChild(sep);
    const clr = document.createElement('button'); clr.type = 'button'; clr.className = 'minimenu-item sq-clear'; clr.textContent = 'Effacer l’historique';
    clr.onclick = () => { close(); writeRecent([]); toast('Historique effacé', 'ok'); };
    panel.appendChild(clr);
  });
}

// initSavedQueries() — câble les 3 affordances de la barre Explore (Enregistrer / Sauvegardées / Récentes).
// Idempotent-safe : appelé une fois au boot. Silencieux si les boutons n'existent pas.
export function initSavedQueries() {
  const save = $('#qsave'), saved = $('#qsaved'), recent = $('#qrecent');
  if (save) save.addEventListener('click', () => saveCurrent());
  if (saved) saved.addEventListener('click', () => openSavedMenu(saved));
  if (recent) recent.addEventListener('click', () => openRecentMenu(recent));
}

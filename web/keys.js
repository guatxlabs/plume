// keys.js — #62 keyboard-driven power-user navigation. PURE WEB (no network). A single document-level
// keydown handler that is DISCOVERABLE (press `?` for a cheatsheet) and NON-INTRUSIVE: it never fires while
// the user is typing in an input/textarea/select/contenteditable, never with Ctrl/Meta/Alt held (so browser
// and OS shortcuts are untouched), and never while a modal overlay is open. Navigation is decoupled from
// app.js: it drives `location.hash` (the SPA's existing router picks it up; a disallowed tab safely falls
// back to Overview), so there is no import cycle.
//
// SHORTCUTS
//   /            focus the Explore search box (switches to Explore first)
//   g then <k>   jump to a view (o overview · e explore · a alerts · c cases · d dashboards · r détection
//                · k savoir · s sources · y système · f flotte · p playbooks · n canaux · h aide)
//   j / k        move the row cursor down / up in the visible list; Enter activates the highlighted row
//   ?            toggle this cheatsheet
//   Esc          close the cheatsheet
import { $, LANG } from './core.js';

// view id reached by `g` + letter. Ids match SPACES tabs in app.js; the router falls back to Overview for a
// tab the current role/mode can't see, so no gating is needed here.
const GMAP = {
  o: 'overview', e: 'explore', a: 'alerts', c: 'cases', d: 'dashboards',
  r: 'detection', k: 'knowledge', s: 'sources', y: 'system', f: 'fleet',
  p: 'playbooks', n: 'notifiers', h: 'help',
};

let pendingG = 0;   // epoch(ms) of the last bare `g`; a following letter within GKEY_MS is a jump

const GKEY_MS = 1200;

function isTyping(el) {
  if (!el) return false;
  if (el.isContentEditable) return true;
  const t = (el.tagName || '').toUpperCase();
  return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT';
}
function modalOpen() { return !!document.querySelector('.modal-ov'); }

function nav(view) {
  if (location.hash.slice(1) === view) return;    // same tab: router won't re-fire, and no need
  location.hash = view;
}

function focusSearch() {
  nav('explore');
  // #q is only shown on Explore; give the router a tick to unhide it, then focus + select.
  setTimeout(() => { const q = $('#q'); if (q) { try { q.focus(); q.select && q.select(); } catch (e) {} } }, 60);
}

// --- j/k row cursor over the visible list (pagedList .qtable rows) --------------------------------------
function visibleSection() {
  const secs = document.querySelectorAll('main > section');
  for (const s of secs) if (!s.hidden && s.offsetParent !== null) return s;
  return null;
}
function cursorRows() {
  const sec = visibleSection(); if (!sec) return [];
  // pagedList renders rows as <tbody><tr> inside table.qtable; scope to the visible view.
  return Array.from(sec.querySelectorAll('table.qtable > tbody > tr'));
}
function moveCursor(delta) {
  const rows = cursorRows(); if (!rows.length) return;
  let idx = rows.findIndex(r => r.classList.contains('krow'));
  rows.forEach(r => r.classList.remove('krow'));
  idx = idx < 0 ? (delta > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, idx + delta));
  const r = rows[idx]; r.classList.add('krow');
  try { r.scrollIntoView({ block: 'nearest' }); } catch (e) {}
}
function activateCursor() {
  const sec = visibleSection(); if (!sec) return false;
  const r = sec.querySelector('table.qtable > tbody > tr.krow');
  if (!r) return false;
  r.click();   // pagedList sets tr.onclick when onRowClick is provided; no-op otherwise
  return true;
}

// --- cheatsheet overlay (reuses the .modal-ov / .modal look) --------------------------------------------
const SHEET = LANG === 'en'
  ? [['/', 'Focus the search box'], ['g then key', 'Jump to a view (o/e/a/c/d/r/k/s/y/f/p/n/h)'],
     ['j / k', 'Move the row cursor down / up'], ['Enter', 'Open the highlighted row'],
     ['?', 'Show / hide this cheatsheet'], ['Esc', 'Close overlays']]
  : [['/', 'Aller à la recherche'], ['g puis touche', 'Sauter vers une vue (o/e/a/c/d/r/k/s/y/f/p/n/h)'],
     ['j / k', 'Déplacer le curseur de ligne bas / haut'], ['Entrée', 'Ouvrir la ligne sélectionnée'],
     ['?', 'Afficher / masquer cette aide'], ['Échap', 'Fermer les surcouches']];
const GHINTS = LANG === 'en'
  ? 'g-jumps: o Overview · e Explore · a Alerts · c Cases · d Dashboards · r Detection · k Knowledge · s Sources · y System · f Fleet · p Playbooks · n Channels · h Help'
  : 'g-sauts : o Vue d\'ensemble · e Explore · a Alertes · c Cases · d Dashboards · r Détection · k Savoir · s Sources · y Système · f Flotte · p Playbooks · n Canaux · h Aide';

function toggleCheatsheet() {
  const existing = document.getElementById('kbd-cheatsheet');
  if (existing) { existing.remove(); return; }
  const ov = document.createElement('div'); ov.className = 'modal-ov'; ov.id = 'kbd-cheatsheet';
  const box = document.createElement('div'); box.className = 'modal kbd-sheet';
  const h = document.createElement('h3'); h.textContent = LANG === 'en' ? 'Keyboard shortcuts' : 'Raccourcis clavier';
  const tbl = document.createElement('table'); tbl.className = 'kbd-table';
  SHEET.forEach(([k, d]) => {
    const tr = document.createElement('tr');
    const kd = document.createElement('td'); kd.className = 'kbd-keys';
    k.split(' ').forEach(part => {
      if (part === 'then' || part === 'puis' || part === '/') { const s = document.createElement('span'); s.className = 'kbd-sep'; s.textContent = part; kd.appendChild(s); }
      else { const kbd = document.createElement('kbd'); kbd.textContent = part; kd.appendChild(kbd); }
    });
    const dd = document.createElement('td'); dd.textContent = d;
    tr.append(kd, dd); tbl.appendChild(tr);
  });
  const hint = document.createElement('p'); hint.className = 'kbd-hint muted'; hint.textContent = GHINTS;
  const act = document.createElement('div'); act.className = 'modal-act';
  const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'm-cancel'; btn.textContent = LANG === 'en' ? 'Close' : 'Fermer';
  act.appendChild(btn); box.append(h, tbl, hint, act); ov.appendChild(box); document.body.appendChild(ov);
  const close = () => ov.remove();
  btn.onclick = close;
  ov.onclick = e => { if (e.target === ov) close(); };
}

// --- the single global handler --------------------------------------------------------------------------
function onKey(e) {
  // never hijack while typing, with modifiers held, or while a modal is open (the cheatsheet closes itself).
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (isTyping(e.target)) return;
  const cheat = document.getElementById('kbd-cheatsheet');
  if (modalOpen()) {
    // the ONLY overlay we own the keys for is our cheatsheet (Esc / ? close it).
    if (cheat && (e.key === 'Escape' || e.key === '?')) { e.preventDefault(); cheat.remove(); }
    return;
  }

  // `g` prefix: a letter within the window jumps to a view.
  if (pendingG && Date.now() - pendingG < GKEY_MS) {
    pendingG = 0;
    const view = GMAP[e.key.toLowerCase()];
    if (view) { e.preventDefault(); nav(view); return; }
    // not a mapped letter -> fall through and treat as a normal key
  }

  switch (e.key) {
    case '/': e.preventDefault(); focusSearch(); return;
    case '?': e.preventDefault(); toggleCheatsheet(); return;
    case 'g': pendingG = Date.now(); return;
    case 'j': e.preventDefault(); moveCursor(1); return;
    case 'k': e.preventDefault(); moveCursor(-1); return;
    case 'Enter': if (activateCursor()) e.preventDefault(); return;
    default: return;
  }
}

// initKeyboardNav() — install the handler once. Safe to call multiple times (guards against double-binding).
export function initKeyboardNav() {
  if (window.__plumeKeysBound) return;
  window.__plumeKeysBound = true;
  document.addEventListener('keydown', onKey);
}

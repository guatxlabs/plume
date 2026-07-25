// prefs.js — #62 per-user UI preferences store (column config, dashboard favorites, per-view settings,
// default time-range). Durable + cross-device: backed by the server (GET/PUT /api/prefs, self-scoped,
// viewer+) with a localStorage MIRROR as a synchronous offline cache/fast-path.
//
// MODEL: a single in-memory object PREFS keyed by short string keys. Reads are synchronous (prefGet);
// writes update memory + the localStorage mirror immediately, then schedule a DEBOUNCED PUT to the server
// (coalesces bursts of edits into one round-trip). On boot, prefsInit() GETs the server blob and reconciles
// (server keys win — they are the durable source of truth across devices), then fires onReady callbacks so
// views can re-apply persisted state (e.g. overview card order). Fully degrades offline: if the network
// fails, the mirror keeps the SPA working; the next successful PUT re-syncs.
//
// SECURITY: the endpoint is self-scoped server-side (keyed by the authenticated identity; the client never
// sends a user id). We never store secrets here — only UI state.
import { api, apiSend } from './core.js';

const LS_KEY = 'plume_prefs';
let PREFS = readMirror();          // synchronous seed from the localStorage mirror (offline-first)
let loaded = false;                // true once the server blob has been reconciled at least once
let putTimer = null;
const readyCbs = [];

function readMirror() { try { return JSON.parse(localStorage.getItem(LS_KEY)) || {}; } catch (e) { return {}; } }
function writeMirror() { try { localStorage.setItem(LS_KEY, JSON.stringify(PREFS)); } catch (e) {} }

// prefGet(key, default) — synchronous read of a preference (default when absent).
export function prefGet(key, dflt) {
  return Object.prototype.hasOwnProperty.call(PREFS, key) ? PREFS[key] : dflt;
}

// prefSet(key, value) — set (or, with value===undefined, delete) a preference. Updates memory + mirror
// immediately and schedules a debounced server PUT. Returns nothing (fire-and-forget; mirror is durable).
export function prefSet(key, value) {
  if (value === undefined) delete PREFS[key]; else PREFS[key] = value;
  writeMirror();
  schedulePut();
}

// prefsReady(cb) — register a callback fired once the server blob is reconciled (or immediately if already
// loaded). Lets a view re-apply persisted state without racing the boot GET.
export function prefsReady(cb) {
  if (typeof cb !== 'function') return;
  if (loaded) { try { cb(PREFS); } catch (e) {} } else readyCbs.push(cb);
}

function schedulePut() {
  if (putTimer) clearTimeout(putTimer);
  putTimer = setTimeout(() => { putTimer = null; flushPrefs(); }, 800);
}

// flushPrefs() — immediately PUT the current blob (used by the debounce + a page-hide flush). Best-effort:
// a failure leaves the durable mirror intact and will retry on the next prefSet.
export async function flushPrefs() {
  try { await apiSend('/prefs', 'PUT', { prefs: PREFS }); } catch (e) { /* offline: mirror holds */ }
}

// prefsInit() — reconcile with the server blob, then fire onReady callbacks. Idempotent-safe to call once
// per authenticated boot. Server keys win (durable cross-device truth); unknown local-only keys are kept.
export async function prefsInit() {
  try {
    const d = await api('/prefs');
    if (d && d.prefs && typeof d.prefs === 'object' && !Array.isArray(d.prefs)) {
      PREFS = Object.assign({}, PREFS, d.prefs);
      writeMirror();
    }
  } catch (e) { /* keep the mirror-seeded PREFS */ }
  loaded = true;
  readyCbs.splice(0).forEach(cb => { try { cb(PREFS); } catch (e) {} });
}

// Flush any pending debounced write when the tab is hidden/closed (don't lose the last edit).
try {
  window.addEventListener('pagehide', () => { if (putTimer) { clearTimeout(putTimer); putTimer = null; flushPrefs(); } });
} catch (e) {}

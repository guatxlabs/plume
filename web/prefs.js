// prefs.js — #62 per-user UI preferences store (column config, dashboard favorites, per-view settings,
// default time-range). Durable + cross-device: backed by the server (GET/PUT /api/prefs, self-scoped,
// viewer+) with a localStorage MIRROR as a synchronous offline cache/fast-path.
//
// MODEL: a single in-memory object PREFS keyed by short string keys. Reads are synchronous (prefGet);
// writes update memory + the localStorage mirror immediately, then schedule a DEBOUNCED PUT to the server
// (coalesces bursts of edits into one round-trip). On boot, prefsInit() GETs the server blob and reconciles,
// then fires onReady callbacks so views can re-apply persisted state (e.g. overview card order). Fully
// degrades offline: if the network fails, the mirror keeps the SPA working; the next successful PUT re-syncs.
//
// RECONCILING IS A REPLACEMENT, NOT A MERGE — and the mirror plays TWO ROLES that must not be conflated:
//   (1) a CACHE of what the server holds, and (2) a BUFFER of writes the server has not acknowledged yet.
// The server (daemon/src/handlers/prefs.rs) stores ONE OPAQUE BLOB per account and a PUT replaces it whole
// (`DO UPDATE SET prefs=excluded.prefs`); it keeps no per-key history, so it cannot tell "deleted" from
// "never set" — absence in its blob IS the deletion, and the blob is therefore the COMPLETE state. Merging
// it into the mirror could only ADD and REPLACE, never REMOVE: a key deleted on device A came back on
// device B (role 1 was being read as role 2) and B's next full-blob PUT re-imposed it on everyone. So we
// REPLACE with the server blob, then re-apply only the keys in PENDING — this device's writes (a set OR a
// delete) that no PUT has acknowledged yet. That keeps the offline contract above literally true while
// letting a deletion be durable. Naive replacement without PENDING would fix the deletion by silently
// discarding unsent offline edits — the same family of defect, pointed the other way.
//
// SECURITY: the endpoint is self-scoped server-side (keyed by the authenticated identity; the client never
// sends a user id). We never store secrets here — only UI state.
import { api, apiSend } from './core.js';

const LS_KEY = 'plume_prefs';
const LS_PENDING = 'plume_prefs_pending';   // key NAMES only — never values; the values live in the mirror
let PREFS = readMirror();          // synchronous seed from the localStorage mirror (offline-first)
const PENDING = readPending();     // keys written HERE that no PUT has acknowledged yet (set OR delete)
let loaded = false;                // true once the server blob has been reconciled at least once
let putTimer = null;
const readyCbs = [];

function readMirror() { try { return JSON.parse(localStorage.getItem(LS_KEY)) || {}; } catch (e) { return {}; } }
function writeMirror() { try { localStorage.setItem(LS_KEY, JSON.stringify(PREFS)); } catch (e) {} }
// PENDING is persisted next to the mirror (same origin, same store) so an edit made offline still counts as
// "unacknowledged" after a reload. It holds KEY NAMES only, and it is a Set — repeated edits of the same key
// never grow it — so it is bounded by the number of DISTINCT top-level pref keys the app writes (four across
// web/ as measured 2026-08-29), not by the number of edits.
function readPending() { try { const a = JSON.parse(localStorage.getItem(LS_PENDING)); return new Set(Array.isArray(a) ? a.filter(k => typeof k === 'string') : []); } catch (e) { return new Set(); } }
function writePending() { try { localStorage.setItem(LS_PENDING, JSON.stringify([...PENDING])); } catch (e) {} }

// prefGet(key, default) — synchronous read of a preference (default when absent).
export function prefGet(key, dflt) {
  return Object.prototype.hasOwnProperty.call(PREFS, key) ? PREFS[key] : dflt;
}

// prefSet(key, value) — set (or, with value===undefined, delete) a preference. Updates memory + mirror
// immediately and schedules a debounced server PUT. Returns nothing (fire-and-forget; mirror is durable).
export function prefSet(key, value) {
  if (value === undefined) delete PREFS[key]; else PREFS[key] = value;
  writeMirror();
  // A DELETE is an intent exactly like a SET, and it is the one the old reconcile could not carry: mark the
  // key unacknowledged either way, so a reconcile that lands before the PUT does not undo it.
  PENDING.add(key);
  writePending();
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
  // Snapshot what THIS round is about to carry, BEFORE the send: apiSend serializes the body synchronously,
  // so a key written while the request is in flight is NOT in it and must stay unacknowledged.
  const sent = [...PENDING];
  try {
    await apiSend('/prefs', 'PUT', { prefs: PREFS });
    sent.forEach(k => PENDING.delete(k));   // acknowledged: the server blob now carries this device's intent
    writePending();
  } catch (e) { /* offline: mirror holds, and PENDING keeps this device's unsent intents */ }
}

// prefsInit() — reconcile with the server blob, then fire onReady callbacks. Idempotent-safe to call once
// per authenticated boot. The server blob REPLACES the mirror (it is the complete cross-device truth, so a
// key missing from it is a DELETION, not a silence); only this device's UNACKNOWLEDGED writes are re-applied
// on top. See the RECONCILING note in the header for why a merge could never carry a removal.
export async function prefsInit() {
  try {
    const d = await api('/prefs');
    if (d && d.prefs && typeof d.prefs === 'object' && !Array.isArray(d.prefs)) {
      const server = Object.assign({}, d.prefs);
      // Re-apply the unsent local intents — a SET restores the value, a DELETE re-removes the key the server
      // still carries. PENDING is NOT cleared here: nothing has acknowledged these yet.
      PENDING.forEach(k => {
        if (Object.prototype.hasOwnProperty.call(PREFS, k)) server[k] = PREFS[k]; else delete server[k];
      });
      PREFS = server;
      writeMirror();
      // Make those intents converge instead of waiting for the user to touch a setting again: the old code
      // relied on "the next successful PUT re-syncs", which never came if the user only read.
      if (PENDING.size) schedulePut();
    }
  } catch (e) { /* keep the mirror-seeded PREFS */ }
  loaded = true;
  readyCbs.splice(0).forEach(cb => { try { cb(PREFS); } catch (e) {} });
}

// Flush any pending debounced write when the tab is hidden/closed (don't lose the last edit).
try {
  window.addEventListener('pagehide', () => { if (putTimer) { clearTimeout(putTimer); putTimer = null; flushPrefs(); } });
} catch (e) {}

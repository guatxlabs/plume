// system.js — #51 DAY-2 OPS : console d'opérabilité « Système ».
//  - self-métriques (CPU/RSS, ingest, latence recherche p50/p95, scheduler, DB, alertes)  -> GET /api/system/metrics
//  - santé R/J/V par composant (ingest/détection/rollups/store/forwarder)                  -> GET /api/system/health
//  - (admin) bulletin/MOTD (setting global, bandeau pour TOUS)                             -> /api/bulletin
//  - (admin) bundle de diagnostic NON-SECRET (support hand-off, téléchargé)               -> GET /api/system/diag
// LECTURE viewer+. Additif : aucun bulletin -> aucun bandeau (invariant mode 0).
import { $, api, apiSend, muted, toast, fmtTs, downloadText, humanAge, socIsAdmin } from './core.js';

// état V/J/R -> classe pastille .fdot (réutilise le vocabulaire de sources.js : frais/warn/muet/calme) + libellé.
const STATE_DOT = { green: 'frais', yellow: 'warn', red: 'muet', idle: 'calme' };
const STATE_LBL = { green: 'OK', yellow: 'attention', red: 'panne', idle: 'inactif' };

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' o';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' Ko';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' Mo';
  return (n / 1073741824).toFixed(2) + ' Go';
}

// S32 — UNE MESURE NON LISIBLE N'EST PAS UN ZÉRO, ET LE PANNEAU NE DOIT PAS LA RENDRE COMME TEL.
// Le serveur OMET le nombre quand sa source n'a pas pu être lue et pose à côté `<clé>_verdict` +
// `<clé>_cause`. Un `?? 0` ou un `fmtBytes(undefined)` reconstruirait ici, côté client, exactement le
// zéro rassurant que le serveur vient de retirer : c'est pourquoi ces tuiles passent par ce lecteur.
// Valeur absente -> tiret cadratin + la cause en sous-titre, jamais « 0 ».
const CAUSE_LBL = {
  aucune: '',
  source_absente: 'source absente',
  source_refusee: 'accès refusé',
  source_illisible: 'source illisible',
  forme_inconnue: 'forme non reconnue',
};

// Le verdict est cherché d'abord PAR CLÉ (`queue_depth_verdict`), puis SUR L'OBJET (`verdict`) : une
// même lecture peut porter plusieurs valeurs — le couple processeur/mémoire vient d'une seule lecture
// de `/proc`, et son verdict est celui de l'objet entier.
function mesureTile(label, obj, cle, fmt, sub) {
  const v = obj[cle];
  if (v == null) {
    const brute = obj[cle + '_cause'] ?? obj.cause;
    const cause = CAUSE_LBL[brute] || brute || 'cause inconnue';
    return tile(label, '—', 'non mesuré : ' + cause);
  }
  return tile(label, fmt(v), sub);
}

function tile(label, value, sub) {
  const d = document.createElement('div');
  d.className = 'sys-tile';
  const v = document.createElement('div'); v.className = 'sys-tile-v'; v.textContent = value;
  const l = document.createElement('div'); l.className = 'sys-tile-l'; l.textContent = label;
  d.append(v, l);
  if (sub) { const s = document.createElement('div'); s.className = 'sys-tile-s muted'; s.textContent = sub; d.appendChild(s); }
  return d;
}

function componentRow(c) {
  const row = document.createElement('div');
  row.className = 'sys-comp';
  const st = String(c.state || 'red');
  const dot = document.createElement('span'); dot.className = 'fdot ' + (STATE_DOT[st] || 'muet');
  const name = document.createElement('b'); name.className = 'sys-comp-n'; name.textContent = c.component;
  const badge = document.createElement('span'); badge.className = 'sys-comp-b sys-' + st; badge.textContent = STATE_LBL[st] || st;
  const detail = document.createElement('span'); detail.className = 'sys-comp-d muted'; detail.textContent = c.detail || '';
  row.append(dot, name, badge, detail);
  return row;
}

async function loadSystemView() {
  const wrap = $('#system-body'); if (!wrap) return;
  let m, h;
  try { [m, h] = await Promise.all([api('/system/metrics'), api('/system/health')]); }
  catch (e) { wrap.replaceChildren(muted('erreur : ' + e.message)); return; }
  wrap.replaceChildren();

  // posture globale
  const posture = h.posture || m.posture || 'green';
  const head = document.createElement('div'); head.className = 'sys-posture';
  const pdot = document.createElement('span'); pdot.className = 'fdot ' + (STATE_DOT[posture] || 'muet');
  const ptxt = document.createElement('b'); ptxt.textContent = 'Posture : ' + (STATE_LBL[posture] || posture);
  const pver = document.createElement('span'); pver.className = 'muted'; pver.style.marginLeft = 'auto';
  pver.textContent = 'plume ' + (m.version || '?') + ' · schéma v' + (m.schema_version || '?') + ' · uptime ' + humanAge(m.uptime_s || 0);
  head.append(pdot, ptxt, pver);
  wrap.appendChild(head);

  // santé par composant
  const comps = document.createElement('div'); comps.className = 'sys-comps';
  (h.components || []).forEach(c => comps.appendChild(componentRow(c)));
  wrap.appendChild(comps);

  // tuiles self-métriques
  const grid = document.createElement('div'); grid.className = 'sys-grid';
  const p = m.process || {}, ing = m.ingest || {}, se = m.search || {}, sc = m.scheduler || {}, db = m.db || {};
  grid.append(
    mesureTile('CPU cumulé', p, 'cpu_seconds', v => v.toFixed(1) + ' s'),
    mesureTile('RSS mémoire', p, 'rss_bytes', fmtBytes),
    tile('Ingest / h', String(ing.events_1h ?? 0), 'total ' + (ing.events_total ?? 0)),
    mesureTile('File spool', ing, 'queue_depth', String, 'fichiers en attente'),
    tile('Recherche p50', (se.p50_ms ?? 0) + ' ms', 'p95 ' + (se.p95_ms ?? 0) + ' ms'),
    tile('Recherches', String(se.requests_total ?? 0), se.samples ? se.samples + ' échantillons' : ''),
    tile('Scheduler', String(sc.rule_ticks_total ?? 0) + ' ticks', sc.rule_last_tick ? 'règles : ' + humanAge(Math.max(0, (m.ts || 0) - sc.rule_last_tick)) : 'démarrage'),
    tile('Rollups', String(sc.rollup_ticks_total ?? 0) + ' ticks', sc.rollup_last_tick ? humanAge(Math.max(0, (m.ts || 0) - sc.rollup_last_tick)) : 'démarrage'),
    mesureTile('Taille base', db, 'size_bytes', fmtBytes),
    tile('Alertes ouvertes', String(m.alerts_open ?? 0)),
    tile('Requêtes HTTP', String((m.http && m.http.requests_total) ?? 0), 'dont 5xx : ' + ((m.http && m.http.responses_5xx_total) ?? 0)),
  );
  wrap.appendChild(grid);

  // ADMIN : bulletin/MOTD + bundle de diagnostic.
  if (socIsAdmin()) {
    wrap.appendChild(adminTools());
  }
}

function adminTools() {
  const box = document.createElement('div'); box.className = 'sys-admin';
  const h = document.createElement('h3'); h.textContent = 'Administration (opérateur)'; box.appendChild(h);

  // --- bulletin / MOTD ---
  const bl = document.createElement('div'); bl.className = 'sys-bulletin';
  const lbl = document.createElement('label'); lbl.textContent = 'Bulletin / MOTD (bandeau diffusé à tous) :'; lbl.className = 'muted';
  const ta = document.createElement('textarea'); ta.id = 'sys-bulletin-msg'; ta.rows = 2; ta.maxLength = 2000;
  ta.placeholder = 'ex : maintenance planifiée 22h-23h — collecte non interrompue';
  const lvl = document.createElement('select'); lvl.id = 'sys-bulletin-level';
  [['info', 'Info'], ['warn', 'Attention'], ['critical', 'Critique']].forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; lvl.appendChild(o); });
  const save = document.createElement('button'); save.className = 'k'; save.type = 'button'; save.textContent = 'Publier';
  const clear = document.createElement('button'); clear.className = 'k-theme'; clear.type = 'button'; clear.textContent = 'Effacer';
  const rowb = document.createElement('div'); rowb.className = 'sys-bulletin-row'; rowb.append(lvl, save, clear);
  bl.append(lbl, ta, rowb);
  // pré-remplit avec le bulletin courant.
  api('/bulletin').then(d => { if (d && d.bulletin) { ta.value = d.bulletin.message || ''; lvl.value = d.bulletin.level || 'info'; } }).catch(() => {});
  save.onclick = async () => {
    try { await apiSend('/bulletin', 'POST', { message: ta.value.trim(), level: lvl.value }); toast('bulletin publié', 'ok'); loadBulletin(); }
    catch (e) { toast('erreur : ' + e.message, 'bad'); }
  };
  clear.onclick = async () => {
    try { await apiSend('/bulletin', 'DELETE'); ta.value = ''; toast('bulletin effacé', 'ok'); loadBulletin(); }
    catch (e) { toast('erreur : ' + e.message, 'bad'); }
  };
  box.appendChild(bl);

  // --- bundle de diagnostic ---
  const dl = document.createElement('div'); dl.className = 'sys-diag';
  const dlbl = document.createElement('span'); dlbl.className = 'muted'; dlbl.textContent = 'Bundle de diagnostic (non-secret, pour le support) : ';
  const dbtn = document.createElement('button'); dbtn.className = 'k-theme'; dbtn.type = 'button'; dbtn.textContent = 'Télécharger le diagnostic';
  dbtn.onclick = async () => {
    try {
      const v = await api('/system/diag');
      downloadText('plume-diag-' + (v.generated_at || Math.floor(Date.now() / 1000)) + '.json', 'application/json', JSON.stringify(v, null, 2));
    } catch (e) { toast('erreur : ' + e.message, 'bad'); }
  };
  dl.append(dlbl, dbtn);
  box.appendChild(dl);
  return box;
}

// Bandeau MOTD (appelé au boot + après une mutation admin). Aucun bulletin -> caché (invariant mode 0).
async function loadBulletin() {
  const el = $('#bulletin-banner'); if (!el) return;
  let d;
  try { d = await api('/bulletin'); } catch { el.hidden = true; return; }
  const b = d && d.bulletin;
  if (!b || !b.message) { el.hidden = true; el.replaceChildren(); return; }
  el.className = 'bulletin-banner lvl-' + (b.level || 'info');
  el.replaceChildren();
  const msg = document.createElement('span'); msg.className = 'bulletin-msg'; msg.textContent = b.message;
  el.appendChild(msg);
  if (b.updated_by) { const by = document.createElement('span'); by.className = 'bulletin-by muted'; by.textContent = '— ' + b.updated_by + (b.updated ? ' · ' + fmtTs(b.updated) : ''); el.appendChild(by); }
  el.hidden = false;
}

export { loadSystemView, loadBulletin };

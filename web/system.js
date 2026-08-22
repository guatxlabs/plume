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

// S32 / S37 — UNE MESURE NON LISIBLE N'EST PAS UN ZÉRO, ET LE PANNEAU NE DOIT PAS LA RENDRE COMME TEL.
// Le serveur OMET le nombre quand sa source n'a pas pu être lue et pose à côté `<clé>_verdict`,
// `<clé>_cause` et `<clé>_detail` (convention d'un seul auteur : `mesure_environnement::Mesure`). Un
// `?? 0` ou un `fmtBytes(undefined)` reconstruirait ici, côté client, exactement le zéro rassurant que
// le serveur vient de retirer. Toute lecture d'une grandeur à verdict passe donc par `lireMesure`, et
// le verdict y est LU, jamais déduit de l'absence du nombre : un verdict autre que `lu` l'emporte sur
// une valeur qui serait tout de même présente, et l'absence des deux est un TROISIÈME état (« non
// publié » : pas encore de tick, serveur qui ne publie pas cette clé) distinct de « non lisible ».
const CAUSE_LBL = {
  aucune: '',
  source_absente: 'source absente',
  source_refusee: 'accès refusé',
  source_illisible: 'source illisible',
  forme_inconnue: 'forme non reconnue',
};
const VERDICT_LU = 'lu';
const VERDICT_ILLISIBLE = 'illisible';

// Le verdict est cherché d'abord PAR CLÉ (`queue_depth_verdict`), puis SUR L'OBJET (`verdict`) : une
// même lecture peut porter plusieurs valeurs — le couple processeur/mémoire vient d'une seule lecture
// de `/proc`, et son verdict est celui de l'objet entier.
// Rend { verdict, valeur, cause, detail } où `verdict` vaut `lu`, `illisible`, un mot inconnu du
// serveur (traité comme NON lu : un verdict ajouté demain est bruyant par défaut, jamais rangé du bon
// côté par inadvertance), ou `null` quand rien n'est publié.
function lireMesure(obj, cle) {
  const verdict = obj[cle + '_verdict'] ?? obj.verdict ?? null;
  const valeur = obj[cle];
  const brute = obj[cle + '_cause'] ?? obj.cause;
  const cause = CAUSE_LBL[brute] ?? (brute || 'cause non dite');
  const detail = obj[cle + '_detail'] ?? obj.detail ?? '';
  if (verdict === VERDICT_LU) return { verdict, valeur, cause, detail };
  if (verdict !== null) return { verdict, valeur: undefined, cause: cause || 'cause non dite', detail };
  // Pas de verdict : un serveur qui ne le publie pas. La valeur seule vaut « lue » ; rien = « non publié ».
  if (valeur != null) return { verdict: VERDICT_LU, valeur, cause: '', detail: '' };
  return { verdict: null, valeur: undefined, cause: '', detail: '' };
}

// Le mot d'état affiché à la place du nombre — jamais un zéro, jamais une case vide.
function motDeVerdict(verdict) {
  return verdict === VERDICT_ILLISIBLE ? 'NON LISIBLE' : verdict === null ? 'non publié' : String(verdict).toUpperCase();
}

// Tuile d'une grandeur à verdict. `fmt` ne reçoit la valeur que si le verdict est `lu` (elle peut
// alors être absente : l'identité de l'hôte publie son verdict SANS sa valeur).
function mesureTile(label, obj, cle, fmt, sub) {
  const m = lireMesure(obj, cle);
  if (m.verdict === VERDICT_LU) return tile(label, fmt(m.valeur), sub);
  const t = tile(label, motDeVerdict(m.verdict), m.verdict === null ? 'aucune mesure publiée' : m.cause, m.detail);
  t.classList.add(m.verdict === null ? 'sys-absent' : 'sys-illisible');
  return t;
}

function tile(label, value, sub, title) {
  const d = document.createElement('div');
  d.className = 'sys-tile';
  const v = document.createElement('div'); v.className = 'sys-tile-v'; v.textContent = value;
  const l = document.createElement('div'); l.className = 'sys-tile-l'; l.textContent = label;
  d.append(v, l);
  if (sub) { const s = document.createElement('div'); s.className = 'sys-tile-s muted'; s.textContent = sub; d.appendChild(s); }
  if (title) d.title = title;
  return d;
}

// P4.1-r / S37 — LE BILAN DU DERNIER TICK DE CHAQUE BOUCLE DE FOND : n abandons, ou un tick AVEUGLE.
// Les boucles sont DÉCOUVERTES dans ce que le serveur publie (`<boucle>_abandons_verdict`), jamais
// énumérées ici : une boucle ajoutée au démon paraît d'office. Un zéro est un VRAI zéro (tout ce qui
// était dû a été évalué) et se lit comme tel ; des abandons sont en alerte ; un tick aveugle est en
// panne, avec sa cause. Aucun bilan publié = démarrage, et c'est dit.
const SUFFIXE_BILAN = '_abandons_verdict';
function bilansDeTicks(sc) {
  const box = document.createElement('div'); box.className = 'sys-bilans';
  const h = document.createElement('div'); h.className = 'sys-tile-l'; h.textContent = 'Abandons au dernier tick, par boucle de fond'; box.appendChild(h);
  const cles = Object.keys(sc).filter(k => k.endsWith(SUFFIXE_BILAN)).sort();
  if (!cles.length) { box.appendChild(muted('aucun bilan publié (pas encore de tick)')); return box; }
  for (const k of cles) {
    const base = k.slice(0, -'_verdict'.length);
    const m = lireMesure(sc, base);
    const row = document.createElement('div'); row.className = 'kv';
    const nom = document.createElement('span'); nom.textContent = base.slice(0, -'_abandons'.length);
    const val = document.createElement('b');
    if (m.verdict === VERDICT_LU) {
      const n = Number(m.valeur) || 0;
      val.textContent = n ? `${n} abandon(s)` : '0';
      val.className = n ? 'warn' : 'ok';
    } else {
      val.textContent = 'TICK AVEUGLE — ' + m.cause;
      val.className = 'bad';
      if (m.detail) val.title = m.detail;
    }
    row.append(nom, val);
    box.appendChild(row);
  }
  return box;
}

// S37 — CE QU'UN COMPOSANT PORTE À CÔTÉ DE SON ÉTAT : toute grandeur à verdict posée sur l'objet
// (`<clé>_verdict`) est lue ; une grandeur NON LISIBLE ou des abandons > 0 sont dits à côté de la
// pastille, même quand l'état du composant ne les reflète pas (la taille de la base n'entre pas dans
// l'état du stockage). Les clés sont découvertes sur l'objet ; le libellé est nommé quand il est connu.
const COMPOSANT_LBL = {
  queue_depth: 'file spool',
  disk_used_pct: 'usage disque',
  db_size_bytes: 'taille base',
  abandons_dernier_passage: 'abandons du dernier passage',
  abandons_dernier_tick: 'abandons du dernier tick',
};
function verdictsDuComposant(c) {
  const out = [];
  for (const k of Object.keys(c).filter(k => k.endsWith('_verdict')).sort()) {
    const base = k.slice(0, -'_verdict'.length);
    const m = lireMesure(c, base);
    const lbl = COMPOSANT_LBL[base] || base;
    const s = document.createElement('span'); s.className = 'sys-comp-v';
    if (m.verdict !== VERDICT_LU) {
      s.textContent = lbl + ' : ' + motDeVerdict(m.verdict) + (m.cause ? ' (' + m.cause + ')' : '');
      s.classList.add('bad');
      if (m.detail) s.title = m.detail;
    } else if (base.startsWith('abandons') && Number(m.valeur) > 0) {
      s.textContent = lbl + ' : ' + m.valeur;
      s.classList.add('warn');
    } else {
      continue;
    }
    out.push(s);
  }
  return out;
}

function componentRow(c) {
  const row = document.createElement('div');
  row.className = 'sys-comp';
  const st = String(c.state || 'red');
  const dot = document.createElement('span'); dot.className = 'fdot ' + (STATE_DOT[st] || 'muet');
  const name = document.createElement('b'); name.className = 'sys-comp-n'; name.textContent = c.component;
  const badge = document.createElement('span'); badge.className = 'sys-comp-b sys-' + st; badge.textContent = STATE_LBL[st] || st;
  const detail = document.createElement('span'); detail.className = 'sys-comp-d muted'; detail.textContent = c.detail || '';
  row.append(dot, name, badge, ...verdictsDuComposant(c), detail);
  return row;
}

async function loadSystemView() {
  const wrap = $('#system-body'); if (!wrap) return;
  let m, h;
  try { [m, h] = await Promise.all([api('/system/metrics'), api('/system/health')]); }
  catch (e) { wrap.replaceChildren(muted('erreur : ' + e.message)); return; }
  rendreSysteme(wrap, m, h);
}

// Le rendu, séparé du chargement : il prend les DEUX réponses telles que le serveur les publie, et c'est
// lui que le témoin de CI exerce sur des objets fabriqués (verdict `illisible`, puis `lu`).
function rendreSysteme(wrap, m, h) {
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
  const p = m.process || {}, ing = m.ingest || {}, se = m.search || {}, sc = m.scheduler || {}, db = m.db || {}, hote = m.host || {};
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
    // S33 — l'identité de l'hôte publie son VERDICT sans sa valeur : lue, ou pourquoi pas.
    mesureTile('Identité hôte', hote, 'identity', () => 'lue', 'décide des actions ciblées'),
    tile('Alertes ouvertes', String(m.alerts_open ?? 0)),
    tile('Requêtes HTTP', String((m.http && m.http.requests_total) ?? 0), 'dont 5xx : ' + ((m.http && m.http.responses_5xx_total) ?? 0)),
  );
  wrap.appendChild(grid);
  wrap.appendChild(bilansDeTicks(sc));

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

export { loadSystemView, loadBulletin, rendreSysteme, lireMesure };

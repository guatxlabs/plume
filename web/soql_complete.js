// soql_complete.js — Complétion IDE-like NATIVE de la barre Explore (#sql).
//
// 100 % natif : aucun LLM/modèle, aucun appel externe. Le vocabulaire (commandes/fonctions/opérateurs/
// champs/valeurs) vient de GET /api/soql/schema — dérivé des consts du compilateur fermé (guatx_core::soql)
// -> la complétion est un SOUS-ENSEMBLE STRICT de ce qui compile (elle ne peut jamais proposer un token que
// `to_sql` rejetterait). Les gabarits viennent de GET /api/soql/templates. Tout est mis en cache une fois.
//
// UX IDE : dropdown contextuel piloté par la position du curseur, ↑/↓ pour naviguer, Tab/Entrée pour
// accepter, Échap pour fermer, re-déclenchement à la frappe, matching fuzzy/préfixe sur le jeton courant.
import { api, apiSend } from './core.js';

let SCHEMA = null;      // { base_keywords, commands, stats_functions, eval_functions, operators, keywords, fields:{core,extended}, values:{category,action,severity,source}, docs:{commands,stats_functions,eval_functions,base_keywords,keywords,operators,fields} }
let TEMPLATES = null;   // [{ id, title, keywords[], soql }]
let loadingMeta = null; // promesse de chargement (dédup)

// Chargement paresseux + caché de la métadonnée de complétion (une seule fois). Silencieux en cas d'échec
// (la complétion se désactive proprement — la barre reste 100 % utilisable sans elle).
async function ensureMeta() {
  if (SCHEMA) return true;
  if (loadingMeta) return loadingMeta;
  loadingMeta = (async () => {
    try {
      const [sc, tp] = await Promise.all([api('/soql/schema'), api('/soql/templates')]);
      SCHEMA = sc || null;
      TEMPLATES = (tp && Array.isArray(tp.templates)) ? tp.templates : [];
      return !!SCHEMA;
    } catch { SCHEMA = null; TEMPLATES = []; return false; }
    finally { loadingMeta = null; }
  })();
  return loadingMeta;
}

// Champs à valeurs connues (enum fermé / inventaire borné) exposés par l'endpoint.
function knownValuesFor(field) {
  if (!SCHEMA || !SCHEMA.values) return null;
  const v = SCHEMA.values;
  if (field === 'category') return (v.category || []).map(x => ({ label: x, insert: x }));
  if (field === 'source') return (v.source || []).map(x => ({ label: x, insert: x }));
  if (field === 'action') return (v.action || []).map(x => ({ label: x, insert: x }));
  if (field === 'severity' || field === 'sev') return (v.severity || []).map(x => ({ label: `${x.value} (${x.label})`, insert: String(x.value) }));
  return null;
}

// ── DOC INLINE : description curée d'un token, servie par /api/soql/schema (clé `docs`). 100 %
// statique. Cherche dans toutes les catégories (commande/fonction/mot-clé/opérateur/champ). null si absent.
function docLookup(token) {
  if (!SCHEMA || !SCHEMA.docs || !token) return null;
  const d = SCHEMA.docs;
  for (const cat of ['commands', 'stats_functions', 'eval_functions', 'base_keywords', 'keywords', 'fields', 'operators']) {
    if (d[cat] && Object.prototype.hasOwnProperty.call(d[cat], token)) return d[cat][token];
  }
  return null;
}

// Description à afficher pour un item de complétion : dérive le token « nu » de l'insert (retire un '('
// de fonction ou un opérateur suffixe type `champ=`), puis interroge la doc. null -> pas de description.
function descForItem(it) {
  if (!it) return null;
  if (it.desc != null) return it.desc;              // description déjà posée à la construction (override)
  let tok = String(it.insert != null ? it.insert : it.label || '').trim();
  const paren = tok.indexOf('(');
  if (paren > 0) tok = tok.slice(0, paren);         // 'sum(' / 'if(' -> 'sum' / 'if'
  let d = docLookup(tok);
  if (d) return d;
  const opM = tok.match(/(=~|>=|<=|!=|=|:|>|<)$/);  // item 'champ=' -> décrire l'opérateur suffixe
  if (opM && SCHEMA.docs && SCHEMA.docs.operators) return SCHEMA.docs.operators[opM[1]] || null;
  return null;
}

function allFields() {
  if (!SCHEMA || !SCHEMA.fields) return [];
  const core = SCHEMA.fields.core || [];
  const ext = SCHEMA.fields.extended || [];
  return [...core.map(f => ({ label: f, insert: f, hint: 'champ' })), ...ext.map(f => ({ label: f, insert: f, hint: 'champ étendu' }))];
}
const isField = (name) => allFields().some(f => f.label === name);

// ── Analyse de CONTEXTE : à partir du texte AVANT le curseur, déduit quel jeu de suggestions proposer et
// combien de caractères remplacer (le jeton partiel courant). Robuste et simple (heuristique par étape).
function analyze(text, pos) {
  const before = text.slice(0, pos);
  const segments = before.split('|');            // découpage grossier par pipe (suffisant pour l'étape active)
  const stageIdx = segments.length - 1;
  const stage = segments[stageIdx];              // texte de l'étape active jusqu'au curseur
  const partial = (stage.match(/(\S*)$/) || ['', ''])[1];  // dernier jeton non terminé
  const before2 = stage.slice(0, stage.length - partial.length); // étape sans le partiel
  const tokens = stage.trim().split(/\s+/).filter(Boolean);

  const mk = (items, opts) => ({ items, replaceLen: (opts && opts.replaceLen != null) ? opts.replaceLen : partial.length, addSpace: !!(opts && opts.addSpace) });

  // Détection field<op>value dans le partiel (base/where) -> valeurs connues.
  const opRe = /^([A-Za-z_][A-Za-z0-9_]*)(=~|>=|<=|!=|=|:|>|<)(.*)$/;
  const filterCtx = (extraFields) => {
    const om = partial.match(opRe);
    if (om) {
      const [, field, , valPartial] = om;
      const vals = knownValuesFor(field);
      if (vals) return mk(vals, { replaceLen: valPartial.length });
      return null; // op déjà tapé mais champ sans valeurs connues -> rien à proposer
    }
    // Jeton = champ connu complet -> proposer les OPÉRATEURS (insère champ+op).
    if (isField(partial)) {
      const ops = (SCHEMA.operators || []).map(o => ({ label: partial + o, insert: partial + o, hint: 'opérateur' }));
      return mk(ops, { replaceLen: partial.length });
    }
    // Sinon -> champs (+ mots-clés de base à l'étape 0).
    return mk((extraFields || []).concat(allFields()));
  };

  // Étape > 0 : encore en train de taper le NOM de commande ? (rien après le 1er jeton)
  if (stageIdx > 0) {
    const afterCmd = stage.replace(/^\s*/, '');
    const cmdWord = (afterCmd.match(/^(\S*)/) || ['', ''])[1];
    if (afterCmd === cmdWord) {
      return mk((SCHEMA.commands || []).map(c => ({ label: c, insert: c, hint: 'commande' })), { addSpace: true });
    }
  }

  const command = stageIdx === 0 ? 'search' : (tokens[0] || '');

  // Étape de BASE (search/metric + filtres).
  if (stageIdx === 0) {
    // Tout début (rien tapé) -> mots-clés de base + commandes usuelles.
    if (before2.trim() === '' ) {
      const base = (SCHEMA.base_keywords || []).map(k => ({ label: k, insert: k, hint: 'base', addSpace: true }));
      return filterCtx(base);
    }
    return filterCtx();
  }

  switch (command) {
    case 'where':
      return filterCtx();
    case 'stats':
    case 'eventstats':
    case 'timechart': {
      const hasBy = tokens.slice(1).includes('by') && before2.includes(' by ');
      if (hasBy) return mk(allFields());
      // 1er argument -> fonctions d'agrégation (+ 'by' et 'span=' pour timechart).
      const fns = (SCHEMA.stats_functions || []).map(f => ({ label: f === 'count' ? 'count' : `${f}(…)`, insert: f === 'count' ? 'count' : `${f}(`, hint: 'fonction' }));
      const extra = [{ label: 'by', insert: 'by', hint: 'groupe', addSpace: true }];
      if (command === 'timechart') extra.unshift({ label: 'span=', insert: 'span=', hint: 'bucket' });
      return mk(fns.concat(extra));
    }
    case 'sort': {
      const neg = partial.startsWith('-');
      const p = neg ? partial.slice(1) : partial;
      const items = allFields().map(f => ({ label: (neg ? '-' : '') + f.label, insert: (neg ? '-' : '') + f.insert, hint: f.hint }));
      return { items, replaceLen: partial.length, addSpace: false, _p: p };
    }
    case 'fields':
    case 'table':
    case 'dedup':
    case 'top':
    case 'rare':
    case 'mvexpand':
    case 'lookup':
      return mk(allFields());
    case 'rename':
      return mk(allFields().concat([{ label: 'as', insert: 'as', hint: 'alias', addSpace: true }]));
    case 'eval': {
      // Après '=' -> fonctions d'eval + champs ; avant '=' (nom de champ neuf) -> rien.
      if (!before2.includes('=')) return null;
      const fns = (SCHEMA.eval_functions || []).map(f => ({ label: `${f}(…)`, insert: `${f}(`, hint: 'fonction' }));
      return mk(fns.concat(allFields()));
    }
    default:
      return null; // head/limit/rate/rex/append/join : pas de complétion de jeton simple
  }
}

// Matching fuzzy/préfixe : préfixe d'abord, puis sous-chaîne. Insensible à la casse. Borne l'affichage.
function filterItems(items, partial) {
  const q = (partial || '').toLowerCase();
  if (!q) return items.slice(0, 40);
  const pre = [], sub = [];
  for (const it of items) {
    const l = it.label.toLowerCase();
    if (l.startsWith(q)) pre.push(it);
    else if (l.includes(q)) sub.push(it);
  }
  return pre.concat(sub).slice(0, 40);
}

// ── Widget dropdown ────────────────────────────────────────────────────────────────────────────────
let box = null, active = -1, curItems = [], curReplaceLen = 0, curAddSpace = false, ta = null;

function ensureBox() {
  if (box) return box;
  box = document.createElement('div');
  box.className = 'soql-ac';
  box.setAttribute('role', 'listbox');
  box.hidden = true;
  document.body.appendChild(box);
  return box;
}

function hide() { if (box) { box.hidden = true; box.innerHTML = ''; } active = -1; curItems = []; }

function positionBox() {
  const r = ta.getBoundingClientRect();
  box.style.left = (window.scrollX + r.left) + 'px';
  box.style.top = (window.scrollY + r.bottom + 2) + 'px';
  box.style.minWidth = Math.min(r.width, 480) + 'px';
}

function render() {
  ensureBox();
  box.innerHTML = '';
  curItems.forEach((it, i) => {
    const row = document.createElement('div');
    row.className = 'soql-ac-item' + (i === active ? ' active' : '');
    row.setAttribute('role', 'option');
    const top = document.createElement('div'); top.className = 'soql-ac-top';
    const lab = document.createElement('span'); lab.className = 'soql-ac-lab'; lab.textContent = it.label;
    top.appendChild(lab);
    if (it.hint) { const h = document.createElement('span'); h.className = 'soql-ac-hint'; h.textContent = it.hint; top.appendChild(h); }
    row.appendChild(top);
    // DOC INLINE : description curée sous la suggestion (+ tooltip). Silencieux si aucune doc.
    const desc = descForItem(it);
    if (desc) { const dd = document.createElement('div'); dd.className = 'soql-ac-desc'; dd.textContent = desc; row.appendChild(dd); row.title = desc; }
    row.addEventListener('mousedown', (e) => { e.preventDefault(); accept(i); });
    box.appendChild(row);
  });
  positionBox();
  box.hidden = curItems.length === 0;
}

function accept(i) {
  const it = curItems[i];
  if (!it) return;
  const pos = ta.selectionStart;
  const start = pos - curReplaceLen;
  let ins = it.insert;
  const addSpace = (it.addSpace != null ? it.addSpace : curAddSpace);
  if (addSpace) ins += ' ';
  ta.value = ta.value.slice(0, start) + ins + ta.value.slice(pos);
  const caret = start + ins.length;
  ta.setSelectionRange(caret, caret);
  hide();
  ta.focus();
  // Re-déclenche : après un champ, montrer les opérateurs ; après une commande, ses arguments.
  setTimeout(trigger, 0);
}

function trigger() {
  if (!SCHEMA) return;
  const pos = ta.selectionStart;
  if (pos !== ta.selectionEnd) return hide();     // sélection multi -> pas de complétion
  const ctx = analyze(ta.value, pos);
  if (!ctx || !ctx.items || !ctx.items.length) return hide();
  const partialForMatch = ctx._p != null ? ctx._p : ta.value.slice(pos - ctx.replaceLen, pos);
  const items = filterItems(ctx.items, partialForMatch);
  if (!items.length) return hide();
  // Évite un dropdown à 1 item déjà tapé en entier (bruit).
  if (items.length === 1 && items[0].label.toLowerCase() === (partialForMatch || '').toLowerCase()) return hide();
  curItems = items; curReplaceLen = ctx.replaceLen; curAddSpace = !!ctx.addSpace; active = 0;
  render();
}

function onKeydown(e) {
  if (box && !box.hidden && curItems.length) {
    if (e.key === 'ArrowDown') { e.preventDefault(); active = (active + 1) % curItems.length; render(); return; }
    if (e.key === 'ArrowUp') { e.preventDefault(); active = (active - 1 + curItems.length) % curItems.length; render(); return; }
    if (e.key === 'Enter' || e.key === 'Tab') {
      // Entrée sans Ctrl/Cmd = accepter la suggestion (Ctrl/Cmd+Entrée reste l'exécution de la requête).
      if (e.key === 'Tab' || (!e.ctrlKey && !e.metaKey)) { e.preventDefault(); accept(active); return; }
      // Ctrl/⌘+Entrée = EXÉCUTE la requête : on FERME le dropdown pour qu'il ne recouvre pas les résultats
      // (sinon la liste de complétion, absolument positionnée sous la barre, intercepte les clics de ligne).
      hide();
    }
    if (e.key === 'Escape') { e.preventDefault(); hide(); return; }
  }
  // Ctrl/Cmd+Espace : forcer l'ouverture.
  if ((e.ctrlKey || e.metaKey) && e.key === ' ') { e.preventDefault(); ensureMeta().then(trigger); }
}

// ── Palette de gabarits (snippet library) ──────────────────────────────────────────────────────────
function openTemplatePalette() {
  ensureMeta().then(() => {
    const ov = document.createElement('div');
    ov.className = 'soql-tpl-ov';
    ov.addEventListener('mousedown', (e) => { if (e.target === ov) ov.remove(); });
    const panel = document.createElement('div'); panel.className = 'soql-tpl-panel';
    const h = document.createElement('div'); h.className = 'soql-tpl-h'; h.textContent = 'Modèles de requête (GXQL)';
    const search = document.createElement('input'); search.type = 'text'; search.className = 'soql-tpl-search';
    search.placeholder = 'Rechercher (ex : ssh, scan, firewall, dns)…'; search.setAttribute('aria-label', 'Rechercher un modèle');
    const list = document.createElement('div'); list.className = 'soql-tpl-list';
    panel.appendChild(h); panel.appendChild(search); panel.appendChild(list); ov.appendChild(panel);
    document.body.appendChild(ov);

    const draw = (q) => {
      list.innerHTML = '';
      const ql = (q || '').toLowerCase().trim();
      const matches = (TEMPLATES || []).filter(t => {
        if (!ql) return true;
        const hay = (t.title + ' ' + t.id + ' ' + (t.keywords || []).join(' ') + ' ' + t.soql).toLowerCase();
        return ql.split(/\s+/).every(w => hay.includes(w));
      });
      if (!matches.length) { const e = document.createElement('div'); e.className = 'soql-tpl-empty'; e.textContent = 'Aucun modèle.'; list.appendChild(e); return; }
      matches.forEach(t => {
        const row = document.createElement('button'); row.type = 'button'; row.className = 'soql-tpl-item';
        const title = document.createElement('div'); title.className = 'soql-tpl-title'; title.textContent = t.title;
        const code = document.createElement('code'); code.className = 'soql-tpl-code'; code.textContent = t.soql;
        row.appendChild(title); row.appendChild(code);
        row.addEventListener('click', () => { if (ta) { ta.value = t.soql; ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); } ov.remove(); });
        list.appendChild(row);
      });
    };
    draw('');
    search.addEventListener('input', () => draw(search.value));
    search.addEventListener('keydown', (e) => { if (e.key === 'Escape') ov.remove(); });
    setTimeout(() => search.focus(), 0);
  });
}

// ── LIVE VALIDATION : compile-as-you-type via POST /api/soql/validate. Côté daemon = COMPILE ONLY
// (to_sql, JAMAIS d'exécution ni de scan event). DÉBOUNCÉ (~300ms), NON-BLOQUANT : purement advisory (✓/✕ +
// message), la barre reste exécutable (le run path re-valide). Anti-spam : timer + skip si inchangé/vide. ──
const VALIDATE_DEBOUNCE_MS = 300;
let validEl = null, validTimer = null, lastValidated = null, validSeq = 0;

function ensureValidEl() {
  if (validEl) return validEl;
  validEl = document.createElement('div');
  validEl.className = 'soql-valid';
  validEl.setAttribute('role', 'status');
  validEl.setAttribute('aria-live', 'polite');
  validEl.hidden = true;
  // Placé juste au-dessus de la zone de suggestions (#sqlhint), sous la barre de requête.
  const hint = document.getElementById('sqlhint');
  if (hint && hint.parentNode) hint.parentNode.insertBefore(validEl, hint);
  else if (ta) { const bar = ta.closest('.qbar') || ta.parentNode; if (bar && bar.parentNode) bar.parentNode.insertBefore(validEl, bar.nextSibling); }
  return validEl;
}

function clearValidity() {
  if (validEl) { validEl.hidden = true; validEl.className = 'soql-valid'; validEl.replaceChildren(); }
  lastValidated = null;
}

function showValidity(ok, msg) {
  ensureValidEl();
  validEl.className = 'soql-valid ' + (ok ? 'ok' : 'err');
  validEl.replaceChildren();
  const ico = document.createElement('span'); ico.className = 'sv-ico'; ico.textContent = ok ? '✓' : '✗'; validEl.appendChild(ico);
  const lab = document.createElement('span'); lab.textContent = ok ? 'Requête valide' : 'Requête invalide'; validEl.appendChild(lab);
  if (!ok && msg) { const m = document.createElement('span'); m.className = 'sv-msg'; m.textContent = msg; validEl.appendChild(m); }
  validEl.hidden = false;
}

// N'applique la validation QU'au GXQL (miroir EXACT du heuristique de app.js) : le SQL brut n'est pas du GXQL
// (compilateur GXQL-only) -> on n'affiche alors aucun avis (l'admin garde le SQL brut, re-validé au run).
function looksLikeSoql(q) { return /^\s*search\b/i.test(q) || /^\s*metric\b/i.test(q) || q.includes('|'); }

function scheduleValidate() {
  if (!ta) return;
  if (validTimer) { clearTimeout(validTimer); validTimer = null; }
  const q = (ta.value || '').trim();
  if (!q) { clearValidity(); return; }                 // vide -> pas d'indicateur, ZÉRO requête
  if (!looksLikeSoql(q)) { clearValidity(); return; }  // SQL brut -> hors compilateur GXQL, pas d'avis
  if (q === lastValidated) return;                     // inchangé depuis le dernier avis -> pas de spam
  validTimer = setTimeout(() => { validTimer = null; runValidate(q); }, VALIDATE_DEBOUNCE_MS);
}

async function runValidate(q) {
  lastValidated = q;
  const seq = ++validSeq;
  try {
    const r = await apiSend('/soql/validate', 'POST', { soql: q });
    if (seq !== validSeq) return;                      // réponse périmée (re-frappe depuis) -> ignorer
    if (!ta || (ta.value || '').trim() !== q) return;  // le texte a changé -> ignorer ce résultat
    if (!r) return;
    showValidity(!!r.valid, r.error || '');
  } catch { /* advisory : silencieux sur échec réseau/gateway — la barre reste 100 % utilisable */ }
}

// ── Init : branche la complétion sur #sql + le bouton palette #qtemplates. Idempotent, non-intrusif. ──
export function initSoqlComplete() {
  ta = document.getElementById('sql');
  if (!ta || ta.dataset.acWired) {
    const btn0 = document.getElementById('qtemplates');
    if (btn0 && !btn0.dataset.acWired) { btn0.dataset.acWired = '1'; btn0.addEventListener('click', openTemplatePalette); }
    return;
  }
  ta.dataset.acWired = '1';
  // Précharge la métadonnée au 1er focus (pas au chargement de page -> zéro coût si l'analyste n'explore pas).
  ta.addEventListener('focus', () => ensureMeta(), { once: true });
  ta.addEventListener('input', () => { scheduleValidate(); ensureMeta().then((ok) => { if (ok) trigger(); }); });
  ta.addEventListener('keydown', onKeydown);
  ta.addEventListener('blur', () => setTimeout(hide, 120)); // délai : laisse le mousedown d'un item passer
  window.addEventListener('resize', () => { if (box && !box.hidden) positionBox(); });

  const btn = document.getElementById('qtemplates');
  if (btn && !btn.dataset.acWired) { btn.dataset.acWired = '1'; btn.addEventListener('click', openTemplatePalette); }
}

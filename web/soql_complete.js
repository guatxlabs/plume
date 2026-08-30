// soql_complete.js — Complétion IDE-like NATIVE de la barre Explore (#sql).
//
// 100 % natif : aucun LLM/modèle, aucun appel externe. Le vocabulaire (commandes/fonctions/opérateurs/
// champs/valeurs) vient de GET /api/soql/schema — dérivé des consts du compilateur fermé (guatx_core::soql)
// -> la complétion est un SOUS-ENSEMBLE STRICT de ce qui compile (elle ne peut jamais proposer un token que
// `to_sql` rejetterait). Les gabarits viennent de GET /api/soql/templates. Tout est mis en cache une fois.
//
// UX IDE : dropdown contextuel piloté par la position du curseur, ↑/↓ pour naviguer, Tab/Entrée pour
// accepter, Échap pour fermer, re-déclenchement à la frappe, matching fuzzy/préfixe sur le jeton courant.
import { api, apiSend, LANG } from './core.js';
import { fetchSaved, saveCurrent, saveAsTemplate, editSaved, deleteSaved, loadIntoBar } from './savedqueries.js';

let SCHEMA = null;      // { base_keywords, commands, stats_functions, eval_functions, operators, keywords, fields:{core,extended}, values:{category,action,severity,source}, docs:{commands,stats_functions,eval_functions,base_keywords,keywords,operators,fields} }
let TEMPLATES = null;   // [{ id, title, keywords[], soql }] — modèles LIVRÉS (bibliothèque embarquée, lecture seule)
let loadingMeta = null; // promesse de chargement (dédup)

// Pose la métadonnée SANS réseau (harnais ESM : éditeur sur un objet fabriqué ; préchargement par un
// appelant qui la détient déjà). Remplace ce que `ensureMeta` aurait chargé.
export function primeCompletionMeta(schema, templates) {
  SCHEMA = schema || null;
  TEMPLATES = Array.isArray(templates) ? templates : [];
}

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

// ── `P11.22-d` — LA LISTE DIT QUAND ELLE EST ÉCOURTÉE, ET NE DIT RIEN QUAND ELLE EST ENTIÈRE ──────
// MESURÉ le 2026-08-30 sur les vingt contextes que `analyze` sait produire, chaque compte étant DÉRIVÉ
// des consts du cœur et non supposé : dix-sept servent de 5 à 28 entrées et la borne n'y mord PAS. Elle
// mord sur `source`, et sur lui seul — le démon sert jusqu'à 500 valeurs distinctes (`SELECT DISTINCT
// source … LIMIT 500`, daemon/src/handlers/soql_meta.rs) quand la boîte n'en rendait que 40 : 460
// disparaissaient sans un mot. Aucune erreur, aucun signe, aucun moyen de soupçonner qu'il manque
// quelque chose — l'exploitant qui n'y trouve pas sa source en conclut qu'elle n'existe pas.
//
// UNE AFFIRMATION A ÉTÉ RÉFUTÉE AVANT D'ÉCRIRE CE CODE, ET ELLE DÉCIDAIT DU GESTE : « la troncature ne
// mord que sur une saisie VIDE » est FAUX. La complétion filtre bel et bien sur ce qui est tapé (mesuré :
// `source=src-12` -> 10 correspondances sur 500, liste ENTIÈRE), mais un préfixe partagé — et les noms de
// source en ont tous un — laisse largement plus que la borne : `source=src-1` -> 100 correspondent,
// 40 rendues, 60 PERDUES. La borne mord donc AUSSI sur une saisie qui filtre déjà.
//
// D'OÙ UN GESTE DOUBLE, DONT LA MOITIÉ PORTANTE EST LA PREMIÈRE.
//  (1) DIRE. Le levier qui resserre EXISTE et il fonctionne ; il ne manquait que de savoir qu'il faut
//      s'en servir. L'aveu le dit — et il ne le dit QUE quand la liste est écourtée : une liste qui
//      avouerait à chaque frappe crierait, et ce qui crie ne se lit pas, donc n'avertit pas.
//  (2) LA BORNE. Elle valait 40, et la plus grande liste FERMÉE que le démon serve en vaut exactement 40
//      (`CIM_CATEGORIES` — mesuré le 2026-08-30 : 40 servies, 40 rendues, 0 perdue). Le plafond était
//      POSÉ SUR le bord d'un énuméré clos : la 41e catégorie aurait été écourtée. Il est porté au DOUBLE
//      de cette plus grande liste fermée, pour ne plus mordre que sur la seule population OUVERTE —
//      `source` —, la seule que l'exploitant puisse effectivement resserrer en tapant.
export const BORNE_DE_SUGGESTIONS_AFFICHEES = 80;

// Bilingue PAR CONSTRUCTION — choix par `LANG`, la forme qu'emploie déjà `core.js`. Cette forme sort de
// la population de la garde de lexique : les deux cliquets de ce module (trous 0, hors-regard 16) sont
// IDENTIQUES des deux côtés du correctif, RELEVÉS le 2026-08-30 plutôt que supposés.
const MOT_DE_LISTE_ECOURTEE = LANG === 'en'
  ? 'list shortened — type more to reach the rest'
  : 'liste écourtée — précisez la saisie pour atteindre le reste';
const JOINT_DU_COMPTE_ECOURTE = LANG === 'en' ? ' of ' : ' sur ';

// Le mot que porte l'aveu, LISIBLE par un témoin sans qu'il ait à le recopier : une garde qui recopie la
// phrase qu'elle juge se dément elle-même le jour où le libellé change.
export function motDeLaListeEcourtee() { return MOT_DE_LISTE_ECOURTEE; }

// DÉCISION PURE, SANS DOM, POUR QU'UN TÉMOIN LA LISE AU LIEU DE LA DEVINER. Matching fuzzy/préfixe :
// préfixe d'abord, puis sous-chaîne, insensible à la casse. Rend les suggestions à AFFICHER **et** le
// nombre de celles qui CORRESPONDENT à la saisie : leur différence est la seule chose qui autorise
// l'aveu, et quand elle est nulle la liste est ENTIÈRE et se tait.
export function suggestionsRetenuesEtLeurCompte(items, partial, borne) {
  const liste = Array.isArray(items) ? items : [];
  const b = (Number.isFinite(borne) && borne > 0) ? borne : BORNE_DE_SUGGESTIONS_AFFICHEES;
  const q = (partial || '').toLowerCase();
  if (!q) return { visibles: liste.slice(0, b), correspondances: liste.length };
  const pre = [], sub = [];
  for (const it of liste) {
    const l = String((it && it.label) || '').toLowerCase();
    if (l.startsWith(q)) pre.push(it);
    else if (l.includes(q)) sub.push(it);
  }
  const retenues = pre.concat(sub);
  return { visibles: retenues.slice(0, b), correspondances: retenues.length };
}

// ── Widget dropdown ────────────────────────────────────────────────────────────────────────────────
let box = null, active = -1, curItems = [], curReplaceLen = 0, curAddSpace = false, ta = null;
// `P11.22-d` — combien d'items CORRESPONDAIENT à la saisie AVANT la borne, et les lignes de SUGGESTION
// dans l'ordre de `curItems`. Cette seconde liste n'est pas un confort : l'aveu est le PREMIER enfant de
// la boîte, si bien que `box.children[active]` ne désigne plus la ligne active. Le lien index -> ligne
// devient EXPLICITE au lieu de reposer sur une coïncidence de position.
let curCorrespondances = 0, lignesRendues = [];

function ensureBox() {
  if (box) return box;
  box = document.createElement('div');
  box.className = 'soql-ac';
  box.setAttribute('role', 'listbox');
  box.hidden = true;
  document.body.appendChild(box);
  return box;
}

function hide() { if (box) { box.hidden = true; box.innerHTML = ''; } active = -1; curItems = []; curCorrespondances = 0; lignesRendues = []; }

function positionBox() {
  const r = ta.getBoundingClientRect();
  box.style.left = (window.scrollX + r.left) + 'px';
  box.style.top = (window.scrollY + r.bottom + 2) + 'px';
  box.style.minWidth = Math.min(r.width, 480) + 'px';
}

// ── `P11.22-c` — LA SÉLECTION SUIT LE DÉFILEMENT, ET ELLE NE BOUGE QUE QUAND ELLE EN SORT ─────────
// MESURÉ le 2026-08-30 : la borne d'affichage valait alors 40 suggestions ; la boîte `.soql-ac` plafonne
// à 280 px, où tiennent 4 lignes portant leur doc sur deux lignes et 8 lignes sans doc. `render()`
// RECONSTRUIT son contenu — `innerHTML = ''` fait disparaître la hauteur, et le document borne alors le
// défilement à zéro — et il est rappelé par CHAQUE flèche, pas seulement par chaque frappe. Aucune mise
// en vue n'existait : une flèche vers le bas au-delà de la 4e ligne surlignait une ligne que personne
// ne voyait, sans erreur et sans qu'un mot le dise.
//
// CE N'EST PAS LE DÉFAUT DE POSITION DE `P11.22-z`/`P11.22-b`, ET LE GESTE COMMUN DE BORNAGE DES POPOVERS
// N'A RIEN À FAIRE ICI : `positionBox` pose la boîte en coordonnées de PAGE (`window.scrollY + r.bottom`),
// là où ce geste-là écrit une position de FENÊTRE — l'y rallier déplacerait la boîte de la hauteur de
// défilement EXACTEMENT. La borne du témoin 56 nomme ce module SAIN pour cette raison précise, et ce
// correctif ne la touche pas : il ne juge que le DEDANS de la boîte, jamais où elle est posée.
// (Son nom n'est pas écrit ici À DESSEIN : cette borne cherche le NOM dans tout le fichier, commentaires
// compris — mesuré le 2026-08-30, l'écrire l'a fait rougir en déclarant un ralliement qui n'existait pas.)
//
// DÉCISION PURE, SANS DOM, POUR QU'UN TÉMOIN LA LISE AU LIEU DE LA DEVINER : rend le défilement à POSER,
// ou `null` quand la ligne active est DÉJÀ dans le champ — et `null` est le cas NOMINAL. Un geste qui
// recentrerait à chaque frappe, ou qui ramènerait en haut sans qu'on le demande, serait PIRE que
// l'immobilité d'aujourd'hui : on n'aligne QUE le bord par lequel la ligne est sortie.
export function defilementQuiGardeLaSuggestionEnVue(vue, ligne) {
  const champ = Number(vue && vue.hauteurVisible), depart = Number(vue && vue.defilement);
  const haut = Number(ligne && ligne.haut), hauteur = Number(ligne && ligne.hauteur);
  // Rien de mesurable (boîte masquée, ou simulacre sans mise en page) -> AUCUN geste. Ne pas bouger vaut
  // toujours mieux que poser un défilement dérivé d'un NaN, qui remettrait la liste en haut.
  if (![champ, depart, haut, hauteur].every(Number.isFinite) || champ <= 0 || hauteur <= 0) return null;
  if (haut < depart) return Math.max(0, haut);                                      // sortie par le HAUT
  if (haut + hauteur > depart + champ) return Math.max(0, haut + hauteur - champ);  // sortie par le BAS
  return null;                                                                      // déjà en vue
}

// Applique la décision sur la boîte réelle. `defilementAvant` est la valeur RELEVÉE avant le vidage :
// la reposer est ce qui empêche la liste de sauter d'un cran à l'autre quand la sélection remonte sur
// une ligne qui était déjà visible. Une seule écriture, et aucune quand rien ne doit bouger.
function garderLaSuggestionActiveEnVue(defilementAvant) {
  if (!box || box.hidden) return;
  const ligne = lignesRendues[active];   // `P11.22-d` — PAS `box.children[active]` : l'aveu occupe le rang 0
  const cible = ligne ? defilementQuiGardeLaSuggestionEnVue(
    { defilement: defilementAvant, hauteurVisible: box.clientHeight },
    { haut: ligne.offsetTop, hauteur: ligne.offsetHeight }) : null;
  const vise = cible == null ? defilementAvant : cible;
  if (Number.isFinite(vise) && vise !== box.scrollTop) box.scrollTop = vise;
}

function render() {
  ensureBox();
  const defilementAvant = box.scrollTop;   // `P11.22-c` — relevé AVANT le vidage, qui le remet à zéro
  box.innerHTML = '';
  lignesRendues = [];
  // `P11.22-d` — L'AVEU EST EN TÊTE, ET C'EST MESURÉ, PAS UN GOÛT. La boîte s'ouvre défilée à zéro avec
  // la première suggestion active : la tête est le seul endroit que l'exploitant regarde à coup sûr. En
  // PIED d'une liste écourtée — jusqu'à quatre-vingts lignes dans une boîte où quatre à huit tiennent —
  // il ne serait jamais lu, et un avertissement qu'on ne lit pas ne vaut pas mieux que le silence.
  // ET IL EST CONDITIONNEL : rien du tout quand la liste est ENTIÈRE, sans quoi il crierait à chaque
  // frappe et cesserait d'avertir. Il défile ensuite avec le contenu — c'est voulu : il a dit ce qu'il
  // avait à dire au moment où la liste s'ouvre, et n'a pas à occuper une ligne sur quatre indéfiniment.
  if (curCorrespondances > curItems.length) {
    const aveu = document.createElement('div');
    aveu.className = 'soql-ac-desc';
    aveu.style.padding = '4px 9px';
    aveu.textContent = curItems.length + JOINT_DU_COMPTE_ECOURTE + curCorrespondances + ' · ' + MOT_DE_LISTE_ECOURTEE;
    aveu.title = aveu.textContent;
    // Ce n'est PAS une suggestion : elle ne s'accepte pas, et son clic ne doit pas sortir l'éditeur du
    // focus — sans quoi l'aveu FERMERAIT la liste qu'il commente.
    aveu.addEventListener('mousedown', (e) => { e.preventDefault(); });
    box.appendChild(aveu);
  }
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
    lignesRendues.push(row);   // `P11.22-d` — le rang dans `curItems`, pas le rang dans la boîte
  });
  positionBox();
  box.hidden = curItems.length === 0;
  garderLaSuggestionActiveEnVue(defilementAvant);
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
  const { visibles, correspondances } = suggestionsRetenuesEtLeurCompte(ctx.items, partialForMatch, BORNE_DE_SUGGESTIONS_AFFICHEES);
  if (!visibles.length) return hide();
  // Évite un dropdown à 1 item déjà tapé en entier (bruit).
  if (visibles.length === 1 && visibles[0].label.toLowerCase() === (partialForMatch || '').toLowerCase()) return hide();
  curItems = visibles; curCorrespondances = correspondances;
  curReplaceLen = ctx.replaceLen; curAddSpace = !!ctx.addSpace; active = 0;
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

// ── Palette « Modèles » : MES MODÈLES (per-user, éditables) + MODÈLES LIVRÉS (bibliothèque, lecture seule) ──
// P11.9-a — UN SEUL endroit pour les modèles. « Enregistrer » (barre) range la requête courante ici ; chaque
// modèle personnel se charge, se MODIFIE (✎) et se SUPPRIME (×) ; un modèle livré se charge ou se COPIE dans
// mes modèles (il devient alors éditable). Charger REMPLIT la barre, n'exécute jamais.
const LIBELLE_PERSONNELS = 'Mes modèles';
const LIBELLE_LIVRES = 'Modèles livrés';
const VIDE_PERSONNELS = 'Aucun modèle personnel — « Enregistrer » range la requête courante ici.';
const VIDE_LIVRES = 'Aucun modèle livré ne correspond.';
const INDISPONIBLES_PERSONNELS = 'Mes modèles : indisponibles (chargement échoué).';

function filtreModeles(liste, q, cles) {
  const ql = (q || '').toLowerCase().trim();
  if (!ql) return liste;
  return liste.filter(t => { const hay = cles(t).toLowerCase(); return ql.split(/\s+/).every(w => hay.includes(w)); });
}

// Rendu PUR de la palette dans `list` (vidée d'abord). `personnels` = null si le chargement a échoué.
// `actions` = { load, edit, remove, copy } — chacune reçoit l'objet ; séparé du DOM pour le harnais.
export function renderTemplatePalette(list, q, personnels, livres, actions) {
  list.innerHTML = '';
  const section = (titre) => { const h = document.createElement('div'); h.className = 'sq-empty soql-tpl-sec'; h.textContent = titre; list.appendChild(h); };
  const vide = (texte) => { const e = document.createElement('div'); e.className = 'soql-tpl-empty'; e.textContent = texte; list.appendChild(e); };
  const ligne = (titre, soql, onLoad, boutons) => {
    // Classes PARTAGÉES (sq-row / sq-load / sq-icon : celles du menu des requêtes) : une ligne de modèle se
    // rend avec le même jeu que les autres listes de la barre — pas de classe sans règle CSS.
    const row = document.createElement('div'); row.className = 'soql-tpl-item sq-row';
    const load = document.createElement('button'); load.type = 'button'; load.className = 'minimenu-item sq-load soql-tpl-load';
    const t = document.createElement('div'); t.className = 'soql-tpl-title'; t.textContent = titre;
    const code = document.createElement('code'); code.className = 'soql-tpl-code'; code.textContent = soql;
    load.append(t, code); load.title = 'Charger dans la barre (sans exécuter)';
    load.addEventListener('click', onLoad);
    row.appendChild(load);
    boutons.forEach(b => row.appendChild(b));
    list.appendChild(row);
    return row;
  };
  const bouton = (texte, titre, cls, onClick) => {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'sq-icon ' + cls; b.textContent = texte; b.title = titre;
    b.addEventListener('click', (e) => { e.stopPropagation(); onClick(); });
    return b;
  };
  section(LIBELLE_PERSONNELS);
  if (personnels === null) vide(INDISPONIBLES_PERSONNELS);
  else {
    const mine = filtreModeles(personnels, q, m => (m.name || '') + ' ' + (m.soql || ''));
    if (!mine.length) vide(VIDE_PERSONNELS);
    mine.forEach(m => ligne(m.name || '(sans nom)', m.soql || '', () => actions.load(m), [
      bouton('✎', 'Modifier ce modèle', 'soql-tpl-edit', () => actions.edit(m)),
      bouton('×', 'Supprimer ce modèle', 'sq-del soql-tpl-del', () => actions.remove(m)),
    ]));
  }
  section(LIBELLE_LIVRES);
  const shipped = filtreModeles(livres || [], q, t => (t.title || '') + ' ' + (t.id || '') + ' ' + (t.keywords || []).join(' ') + ' ' + (t.soql || ''));
  if (!shipped.length) vide(VIDE_LIVRES);
  shipped.forEach(t => ligne(t.title || t.id || '(sans titre)', t.soql || '', () => actions.load(t), [
    bouton('⧉', 'Copier dans mes modèles (pour le modifier)', 'soql-tpl-copy', () => actions.copy(t)),
  ]));
}

function openTemplatePalette() {
  Promise.all([ensureMeta(), fetchSaved()]).then(([, personnels]) => {
    const ov = document.createElement('div');
    ov.className = 'soql-tpl-ov';
    ov.addEventListener('mousedown', (e) => { if (e.target === ov) ov.remove(); });
    const panel = document.createElement('div'); panel.className = 'soql-tpl-panel';
    const head = document.createElement('div'); head.className = 'soql-tpl-h';
    const h = document.createElement('span'); h.textContent = 'Modèles de requête (GXQL)';
    // Pas de `crud-btn` ici : `/api/saved-queries` est self-service viewer+ (rbac.rs -> MinRole::Read, POST/PUT/
    // DELETE compris, le handler posant `owner = appelant`). Un lecteur gere SES modeles — comme les boutons
    // modifier/supprimer voisins, qui n'ont jamais porte la classe.
    const add = document.createElement('button'); add.type = 'button'; add.className = 'picon soql-tpl-add'; add.textContent = '+ Enregistrer la requête courante';
    add.title = 'Enregistrer le texte de la barre dans mes modèles';
    head.append(h, add);
    const search = document.createElement('input'); search.type = 'text'; search.className = 'soql-tpl-search';
    search.placeholder = 'Rechercher (ex : ssh, scan, firewall, dns)…'; search.setAttribute('aria-label', 'Rechercher un modèle');
    const list = document.createElement('div'); list.className = 'soql-tpl-list';
    panel.appendChild(head); panel.appendChild(search); panel.appendChild(list); ov.appendChild(panel);
    document.body.appendChild(ov);

    let mine = personnels;
    const recharger = () => fetchSaved().then(p => { mine = p; draw(search.value); });
    const actions = {
      load: (m) => { loadIntoBar(m.soql || ''); ov.remove(); },
      edit: (m) => editSaved(m, recharger),
      remove: (m) => deleteSaved(m, recharger),
      copy: (t) => saveAsTemplate({ name: t.title || t.id || '', soql: t.soql || '' }).then(r => { if (r) recharger(); }),
    };
    const draw = (q) => renderTemplatePalette(list, q, mine, TEMPLATES || [], actions);
    add.addEventListener('click', () => saveCurrent().then(r => { if (r) recharger(); }));
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
  // P11.9-b — L'ÉDITEUR N'A PAS DE LIGATURES. MESURÉ le 2026-08-22 : aucune séquence de frappe ne fait
  // réécrire `!=` par ce module (témoin dans le harnais ESM) ; en revanche la police monospace livrée
  // (JetBrains Mono, `calt` actif par défaut) porte 138 ligatures dont `!=`, `<=`, `>=`, `||`, `|>` et
  // `..` — un « différent » tapé s'AFFICHE comme un seul glyphe barré que l'œil lit « égal ». Dans un
  // éditeur de requêtes, la forme tapée doit être la forme vue : ligatures coupées sur l'éditeur.
  // (La règle CSS durable vit dans style.css ; cette pose inline garantit la propriété depuis le module
  // qui possède l'éditeur, et le harnais la tient.)
  ta.style.fontVariantLigatures = 'none';
  // Précharge la métadonnée au 1er focus (pas au chargement de page -> zéro coût si l'analyste n'explore pas).
  ta.addEventListener('focus', () => ensureMeta(), { once: true });
  ta.addEventListener('input', () => { scheduleValidate(); ensureMeta().then((ok) => { if (ok) trigger(); }); });
  ta.addEventListener('keydown', onKeydown);
  ta.addEventListener('blur', () => setTimeout(hide, 120)); // délai : laisse le mousedown d'un item passer
  window.addEventListener('resize', () => { if (box && !box.hidden) positionBox(); });

  const btn = document.getElementById('qtemplates');
  if (btn && !btn.dataset.acWired) { btn.dataset.acWired = '1'; btn.addEventListener('click', openTemplatePalette); }
}

// Exposés pour le harnais ESM (séquence de frappe sur un éditeur fabriqué) ; aucun usage applicatif.
export { analyze, trigger, accept };

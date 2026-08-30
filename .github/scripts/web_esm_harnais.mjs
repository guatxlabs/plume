#!/usr/bin/env node
// Harnais ESM de la surface web — shim DOM minimal, aucun cadre de test, aucun réseau.
//
// CE QU'IL PROUVE, ET RIEN D'AUTRE
// --------------------------------
// 1. LE GRAPHE DE MODULES SE LIE. Depuis le découpage de `app.js` en modules ES, un import d'un
//    symbole déplacé est une `SyntaxError` à l'édition de liens (« does not provide an export
//    named … ») : le module échoue, la cascade remonte jusqu'à `app.js`, `route()` ne pose jamais
//    `app-ready`, et l'interface reste VIDE — le shell seul visible. Aucun test Rust ne peut le voir.
//    Chaque module suivi sous `web/` est importé ici, dans un processus Node muni d'un `document`
//    factice ; une erreur de lien nomme le module et le symbole.
// 2. LE VERDICT D'UNE GRANDEUR EST RENDU (`S37`). Le démon publie `<clé>_verdict` / `<clé>_cause` /
//    `<clé>_detail` à côté d'une grandeur (`S32`), et la surface doit rendre un ÉTAT quand le verdict
//    n'est pas « lu » — jamais un zéro, jamais une case vide. Le panneau Système est rendu sur des
//    objets fabriqués : verdict `illisible` sur chaque famille (mesure, verdict sans valeur, bilan de
//    boucle, grandeur de composant), puis verdict `lu` — le second témoin interdit qu'une version qui
//    dirait TOUJOURS « non lisible » passe le premier.
//
// Le shim ne rend pas de mise en page : il enregistre l'arbre que les modules construisent, et
// c'est le TEXTE de cet arbre qui est jugé. `fetch` est absent par construction : aucun témoin ne
// dépend du réseau, et une lecture réseau échoue ici au lieu de partir.
// CE QUE CETTE ABSENCE NE PROUVE PAS, et le commentaire qui vivait ici l'affirmait à tort : elle NE
// REFUSE PAS un appel réseau au chargement d'un module. La console en fait — elle doit peindre à
// l'amorçage — et l'échec de `fetch` retombe dans le `catch` de la charge, donc rien ne rougit. Ce
// harnais ne verrait un tel appel que s'il produisait un rejet NON TRAITÉ. Mesuré le 2026-08-25 :
// c'est ce qui est arrivé en dérivant les charges de la vue, et c'est ce qui a fait apparaître une
// récursion sans fin — utile, mais par accident, pas par construction.
import { readdirSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
const WEB = path.join(RACINE, "web");

// ---------------------------------------------------------------------------------------------
// SHIM DOM — le strict nécessaire pour que les modules se chargent et construisent un arbre.
// ---------------------------------------------------------------------------------------------
class Element {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    // `P11.13-g` — `children` ET `childNodes` NE SONT PAS LA MÊME LISTE. Le document réel range TOUS les
    // nœuds (texte compris) dans `childNodes` et n'expose que les ÉLÉMENTS dans `children`. Le shim n'avait
    // qu'une liste, ce qui restait sans conséquence tant qu'aucun nœud texte n'existait — et le balisage
    // posé en bloc n'en créait aucun. Dès qu'il en crée, confondre les deux fait apparaître un nœud texte
    // là où tout le code (celui de la console comme celui de ce banc) attend un élément.
    this._enfants = [];
    this._v = 0;
    this.parentNode = null;
    this.attributes = {};
    this.style = {};
    this.hidden = false;
    this.value = "";
    this.options = [];
    this.selectedIndex = -1;
    this._text = "";
    this._classes = new Set();
    this.classList = {
      add: (...c) => c.forEach((x) => this._classes.add(x)),
      remove: (...c) => c.forEach((x) => this._classes.delete(x)),
      toggle: (x, f) => { if (f === undefined ? !this._classes.has(x) : f) this._classes.add(x); else this._classes.delete(x); },
      contains: (x) => this._classes.has(x),
    };
  }
  get className() { return [...this._classes].join(" "); }
  set className(v) { this._classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  // Le filtre est MÉMOÏSÉ sur un compteur de version, et il n'alloue rien quand aucun nœud texte n'est
  // là : sans ces deux précautions, séparer les deux listes coûtait le banc à chaque lecture d'enfants.
  get children() { if (this._vCache !== this._v) { this._cacheEnfants = this._enfants.some((n) => !n.tagName) ? this._enfants.filter((n) => n.tagName) : this._enfants; this._vCache = this._v; } return this._cacheEnfants; }
  get textContent() { return this._text + this._enfants.map((c) => c.textContent).join(""); }
  set textContent(v) { this._text = String(v ?? ""); this._enfants.forEach((c) => { if (c && c.parentNode === this) c.parentNode = null; }); this._enfants = []; this._v++; this._html = undefined; }
  // `P11.13-g` — POSER DU BALISAGE CONSTRUIT UN SOUS-ARBRE. La chaîne posée reste retenue TELLE QUELLE
  // tant que rien n'a bougé dessous — c'est ce que le document réel rendrait, au caractère près, et
  // plusieurs témoins la passent au crible. DÈS QU'UN NŒUD BOUGE, elle est PÉRIMÉE et la relecture
  // repart de l'arbre : rendre la chaîne d'origine dirait alors que le déplacement n'a pas eu lieu.
  get innerHTML() { return this._html !== undefined ? this._html : this._enfants.map(serialiser).join(""); }
  get outerHTML() { return serialiser(this); }
  set innerHTML(v) { this._html = String(v); this._enfants.forEach((c) => { if (c && c.parentNode === this) c.parentNode = null; }); this._enfants = []; this._v++; this._text = ""; analyserBalisage(this._html, this, false); }
  get innerText() { return this.textContent; }
  set innerText(v) { this.textContent = v; }
  get firstChild() { return this._enfants[0] ?? null; }
  get lastChild() { return this._enfants[this._enfants.length - 1] ?? null; }
  get childNodes() { return this._enfants; }
  get firstElementChild() { return this.children[0] ?? null; }
  get nextElementSibling() { const f = this.parentNode && this.parentNode.children; if (!f) return null; const i = f.indexOf(this); return i >= 0 ? f[i + 1] ?? null : null; }
  // `P11.13-g` — « RATTACHÉ » A DÉSORMAIS UNE RÉPONSE, ET UNE SEULE. Ce prédicat rendait TOUJOURS vrai,
  // ce qui contredit le chemin d'un événement (un nœud détaché ne réveille pas les capteurs du document) :
  // un instrument qui répond deux choses différentes à la même question n'en mesure aucune.
  get isConnected() { for (let n = this; n; n = n.parentNode) if (n === document.body || n === document.documentElement) return true; return false; }
  // `P11.13-e` — INSÉRER DÉTACHE. Le document réel RETIRE un nœud de son parent précédent avant de le
  // poser ailleurs : un nœud n'a jamais deux parents. Le shim posait le nouveau parent sans retirer
  // l'enfant de l'ancienne liste, si bien qu'un élément DÉPLACÉ restait listé sous les deux — et une
  // mesure a conclu qu'un formulaire restait joignable après la fermeture des modales alors qu'il ne
  // l'était pas. L'instrument a produit un faux négatif sur le défaut même qu'il servait à établir.
  _detacher(n) { const p = n && n.parentNode; if (p) { p._enfants = p._enfants.filter((x) => x !== n); p._v++; } return n; }
  appendChild(c) { if (c instanceof Fragment) { [...c._enfants].forEach((x) => this.appendChild(x)); return c; } this._detacher(c); c.parentNode = this; this._enfants.push(c); this._v++; this._html = undefined; return c; }
  append(...cs) { cs.forEach((c) => this.appendChild(typeof c === "string" ? document.createTextNode(c) : c)); }
  prepend(...cs) { cs.reverse().forEach((c) => { const n = typeof c === "string" ? document.createTextNode(c) : c; this._detacher(n); n.parentNode = this; this._enfants.unshift(n); this._v++; this._html = undefined; }); }
  replaceChildren(...cs) { this._enfants.forEach((c) => { if (c && c.parentNode === this) c.parentNode = null; }); this._enfants = []; this._v++; this._text = ""; this._html = undefined; this.append(...cs); }
  insertBefore(n, ref) { this._detacher(n); const i = this._enfants.indexOf(ref); n.parentNode = this; if (i < 0) this._enfants.push(n); else this._enfants.splice(i, 0, n); this._v++; this._html = undefined; return n; }
  removeChild(c) { this._enfants = this._enfants.filter((x) => x !== c); this._v++; this._html = undefined; if (c && c.parentNode === this) c.parentNode = null; return c; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  replaceWith(...cs) { if (!this.parentNode) return; const p = this.parentNode, i = p._enfants.indexOf(this); p._enfants.splice(i, 1, ...cs); p._v++; p._html = undefined; this.parentNode = null; cs.forEach((c) => (c.parentNode = p)); }
  // ATTRIBUTS REFLÉTÉS (`P11.8-d`). Un navigateur REFLÈTE ces propriétés IDL dans l'attribut du même nom :
  // `el.placeholder = '…'` POSE l'attribut, et `setAttribute('placeholder', …)` change la propriété. Le shim
  // ne le faisait pas, et c'était un TROU DE TÉMOIN, pas un détail : `i18nWalk` lit et écrit les libellés
  // affichés PAR ATTRIBUT, donc une valeur posée par propriété était intraduisible ici — sa clé pouvait être
  // au lexique et sa valeur anglaise n'être jamais rendue sans que rien ne rougisse. Mesuré dans `web/` le
  // 2026-08-24 : 228 valeurs affichées sont posées par propriété (201 `title`, 25 `placeholder`, 2 `label`),
  // aucune n'était témoignée en anglais. Un navigateur rend "" et non `null` pour ces trois-là non posées.
  get title() { return this.attributes.title ?? ""; }
  set title(v) { this.setAttribute("title", v); }
  get placeholder() { return this.attributes.placeholder ?? ""; }
  set placeholder(v) { this.setAttribute("placeholder", v); }
  get label() { return this.attributes.label ?? ""; }
  set label(v) { this.setAttribute("label", v); }
  // `P11.15-a` — `type` EST REFLÉTÉ LUI AUSSI. Le document réel POSE l'attribut quand la propriété est
  // écrite (`b.type = 'button'`), et c'est par l'ATTRIBUT qu'un bouton typé se distingue d'un bouton qui
  // vaut « submit » dans un formulaire. Le shim n'en gardait qu'une propriété JavaScript : un témoin qui
  // lisait l'attribut voyait `null` sur un bouton correctement typé, et un bouton NON typé lui aurait
  // rendu la même chose — deux situations opposées, un seul verdict.
  get type() { return this.attributes.type ?? ""; }
  set type(v) { this.setAttribute("type", v); }
  // `P11.13-g` — `disabled` EST UN ATTRIBUT BOOLÉEN, et il ne l'était pas ici : `el.disabled = true`
  // ne posait qu'une propriété JavaScript, invisible à `hasAttribute`, à `getAttribute` et au sélecteur
  // `[disabled]`. Le banc en est resté aveugle à une régression réelle où un geste S'ANNULAIT LUI-MÊME
  // sans un mot. Un attribut booléen vaut "" quand il est posé, et il est RETIRÉ quand la propriété
  // retombe à faux — ce n'est pas `disabled="false"`.
  get disabled() { return this.hasAttribute("disabled"); }
  set disabled(v) { if (v) this.setAttribute("disabled", ""); else this.removeAttribute("disabled"); }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  removeAttribute(k) { delete this.attributes[k]; }
  hasAttribute(k) { return k in this.attributes; }
  // `P11.13-g` — LES GESTIONNAIRES D'ÉVÉNEMENTS ÉTAIENT DES COQUILLES VIDES. `addEventListener` ne
  // retenait rien, `dispatchEvent` rendait `true` sans rappeler personne, et `click()` ne faisait rien :
  // POSER un écouteur ne prouve rien du chemin réel de la frappe, et un témoin qui se contentait de la
  // pose a failli valider une recherche NON FONCTIONNELLE. Les écouteurs sont désormais retenus et
  // rappelés le long du chemin réel — capture depuis le document, cible, puis remontée — avec `target`,
  // `preventDefault` et `stopPropagation` observés. La délégation (`e.target.closest('…')`), qui est le
  // câblage majoritaire de la console, en dépend : `closest` rendait `null`, donc tout chemin délégué
  // s'arrêtait au premier test.
  addEventListener(type, rappel, options) { if (typeof rappel !== "function") return; (this._ecouteurs || (this._ecouteurs = [])).push({ type: String(type), rappel, capture: options === true || !!(options && options.capture), once: !!(options && options.once) }); }
  removeEventListener(type, rappel, options) { const c = options === true || !!(options && options.capture); this._ecouteurs = (this._ecouteurs || []).filter((e) => !(e.type === String(type) && e.rappel === rappel && e.capture === c)); }
  dispatchEvent(ev) { return distribuer(this, ev); }
  focus() {} blur() {} scrollIntoView() {} select() {}
  click() { return distribuer(this, new Evenement("click", { bubbles: true })); }
  matches(sel) { return String(sel).split(",").some((b) => etapeCorrespond(this, b.trim())); }
  closest(sel) { for (let n = this; n; n = n.parentNode) { if (n.tagName && String(sel).split(",").some((b) => etapeCorrespond(n, b.trim()))) return n; } return null; }
  get parentElement() { return this.parentNode && this.parentNode.tagName && this.parentNode !== document ? this.parentNode : null; }
  // `P11.13-g` — `dataset` NE REFLÉTAIT RIEN. C'était un objet nu : `el.dataset.act = 'ack'` ne posait
  // aucun attribut `data-act`, et un `data-act` venu du balisage ne se lisait pas en `dataset.act`. Deux
  // conséquences mesurées : un palier cliqué posait une valeur INDÉFINIE, et le sélecteur `[data-act=…]`
  // — le câblage de délégation le plus employé de la console — ne trouvait jamais ce que le code venait
  // de poser. La vue est PARESSEUSE (un mandataire par élément touché, pas par élément créé) : la page
  // en compte des milliers et le banc doit rester jouable à chaque changement.
  get dataset() { return this._dataset || (this._dataset = mandataireDeDonnees(this)); }
  contains(n) { return n === this || this._enfants.some((c) => c.contains && c.contains(n)); }
  getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0, right: 0, bottom: 0 }; }
  querySelector() { return new Element("div"); }
  querySelectorAll() { return []; }
  getContext() { return null; }
  cloneNode() { const e = new Element(this.tagName); e.className = this.className; e._text = this._text; e.id = this.id; Object.assign(e.attributes, this.attributes); return e; }
}
class Text { constructor(t) { this._t = String(t); this.parentNode = null; } get textContent() { return this._t; } set textContent(v) { this._t = String(v); } contains() { return false; } }
class Fragment extends Element { constructor() { super("#fragment"); } }

// La relecture d'un sous-arbre QUI A BOUGÉ depuis la pose : le shim ne peut plus rendre la chaîne
// d'origine sans mentir, il la reconstruit. L'ordre des attributs n'est pas celui de la source
// (`id` et `class` sont rangés à part) — c'est une DIFFÉRENCE, pas une omission, et elle ne porte que
// sur les nœuds mutés après coup.
const echapperTexte = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const echapperValeur = (t) => echapperTexte(t).replace(/"/g, "&quot;");
function serialiser(n) {
  if (!n || !n.tagName) return echapperTexte(n ? n.textContent : "");
  const at = [];
  if (n.id) at.push(`id="${echapperValeur(n.id)}"`);
  if (n.className) at.push(`class="${echapperValeur(n.className)}"`);
  for (const [k, v] of Object.entries(n.attributes)) if (k !== "id" && k !== "class") at.push(`${k}="${echapperValeur(v)}"`);
  if (n.hidden && !("hidden" in n.attributes)) at.push("hidden=\"\"");
  const tag = n.tagName.toLowerCase(), ouvre = `<${tag}${at.length ? " " + at.join(" ") : ""}>`;
  if (VIDES.has(tag)) return ouvre;
  return ouvre + echapperTexte(n._text) + n._enfants.map(serialiser).join("") + `</${tag}>`;
}

// Le nom d'un attribut `data-*` et la clé de `dataset` sont la MÊME donnée dans deux graphies :
// `data-ac-wired` <-> `acWired`. Les deux sens sont écrits ici une seule fois.
const versAttribut = (cle) => "data-" + String(cle).replace(/[A-Z]/g, (c) => "-" + c.toLowerCase());
const versCle = (attr) => attr.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
const mandataireDeDonnees = (el) => new Proxy(Object.create(null), {
  get: (_, k) => (typeof k === "string" && el.hasAttribute(versAttribut(k)) ? el.getAttribute(versAttribut(k)) : undefined),
  set: (_, k, v) => { el.setAttribute(versAttribut(k), v); return true; },
  has: (_, k) => typeof k === "string" && el.hasAttribute(versAttribut(k)),
  deleteProperty: (_, k) => { el.removeAttribute(versAttribut(k)); return true; },
  ownKeys: () => Object.keys(el.attributes).filter((a) => a.startsWith("data-")).map(versCle),
  getOwnPropertyDescriptor: (_, k) => (typeof k === "string" && el.hasAttribute(versAttribut(k)) ? { value: el.getAttribute(versAttribut(k)), enumerable: true, configurable: true, writable: true } : undefined),
});

// `P11.13-g` — LE CHEMIN RÉEL D'UN ÉVÉNEMENT. Un événement du document réel descend en CAPTURE depuis
// le document jusqu'au parent de la cible, atteint la cible, puis REMONTE ; `target` désigne la cible,
// jamais le nœud qui écoute ; `preventDefault` et `stopPropagation` ont un effet observable. Le shim
// n'en avait rien : la pose était enregistrée (pour le document seulement) et la frappe n'arrivait
// nulle part. Un objet nu (`{ type: 'input' }`) reste accepté — plusieurs témoins en fabriquent — et
// se voit compléter ce qui manque, pour que le même chemin le porte.
class Evenement {
  constructor(type, init = {}) {
    Object.assign(this, init);
    this.type = String(type);
    this.bubbles = init.bubbles !== false;
    this.target = init.target ?? null;
    this.currentTarget = null;
    this.defaultPrevented = false;
    this._arrete = false;
  }
  preventDefault() { this.defaultPrevented = true; }
  stopPropagation() { this._arrete = true; }
  stopImmediatePropagation() { this._arrete = true; }
}
const ecouteursDe = (n, type, capture) => {
  const l = n === document ? ecouteursDuDocument : n._ecouteurs;
  return (l || []).filter((e) => e.type === type && !!e.capture === capture);
};
function distribuer(cible, ev) {
  if (!ev || typeof ev !== "object") return true;
  if (typeof ev.preventDefault !== "function") ev.preventDefault = function () { this.defaultPrevented = true; };
  if (typeof ev.stopPropagation !== "function") ev.stopPropagation = function () { this._arrete = true; };
  if (typeof ev.stopImmediatePropagation !== "function") ev.stopImmediatePropagation = ev.stopPropagation;
  if (ev.target == null) ev.target = cible;
  const type = String(ev.type);
  const chemin = [];
  for (let n = cible; n; n = n.parentNode) chemin.push(n);
  // Le document n'est en bout de chemin que si la cible y est RATTACHÉE : un nœud détaché ne fait pas
  // remonter son clic jusqu'aux capteurs globaux, et c'est ce qui distingue « posé » de « joignable ».
  if (chemin[chemin.length - 1] === document.body) chemin.push(document);
  const appeler = (n, e) => { ev.currentTarget = n; try { e.rappel.call(n, ev); } finally { if (e.once) n.removeEventListener(e.type, e.rappel, e.capture); } };
  for (let i = chemin.length - 1; i > 0 && !ev._arrete; i--) for (const e of ecouteursDe(chemin[i], type, true)) { appeler(chemin[i], e); if (ev._arrete) break; }
  if (!ev._arrete) {
    for (const e of [...ecouteursDe(cible, type, true), ...ecouteursDe(cible, type, false)]) { appeler(cible, e); if (ev._arrete) break; }
    const propre = cible["on" + type];
    if (typeof propre === "function") { ev.currentTarget = cible; propre.call(cible, ev); }
  }
  if (ev.bubbles !== false) for (let i = 1; i < chemin.length && !ev._arrete; i++) {
    for (const e of ecouteursDe(chemin[i], type, false)) { appeler(chemin[i], e); if (ev._arrete) break; }
    const propre = chemin[i]["on" + type];
    if (typeof propre === "function" && !ev._arrete) { ev.currentTarget = chemin[i]; propre.call(chemin[i], ev); }
  }
  ev.currentTarget = null;
  return !ev.defaultPrevented;
}

const stockage = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear(), key: (i) => [...m.keys()][i] ?? null, get length() { return m.size; } }; };

const document = {
  documentElement: new Element("html"),
  head: new Element("head"),
  body: new Element("body"),
  title: "",
  cookie: "",
  hidden: false,
  visibilityState: "visible",
  readyState: "complete",
  createElement: (t) => new Element(t),
  createElementNS: (_ns, t) => new Element(t),
  createTextNode: (t) => new Text(t),
  createDocumentFragment: () => new Fragment(),
  // Jamais `null` : un module qui câble `$('#x').onclick = …` au chargement ne doit pas s'arrêter ici.
  querySelector: () => new Element("div"),
  querySelectorAll: () => [],
  getElementById: () => new Element("div"),
  // Le shim ne DISPATCHE rien de lui-même, mais il ENREGISTRE ce que la console câble sur le document :
  // un capteur en phase de capture est un mécanisme partagé, et un mécanisme qu'aucun témoin ne peut
  // rappeler est un mécanisme que rien n'empêche de disparaître (le témoin 32 rappelle le sien).
  addEventListener(type, rappel, options) { if (typeof rappel !== "function") return; ecouteursDuDocument.push({ type: String(type), rappel, capture: options === true || !!(options && options.capture), once: !!(options && options.once) }); },
  removeEventListener(type, rappel, options) { const c = options === true || !!(options && options.capture); const i = ecouteursDuDocument.findIndex((e) => e.type === String(type) && e.rappel === rappel && !!e.capture === c); if (i >= 0) ecouteursDuDocument.splice(i, 1); },
  dispatchEvent(ev) { return distribuer(document, ev); },
  execCommand: () => false,
};
const ecouteursDuDocument = [];
// Les observateurs de mutations restent INERTES (le shim ne mute rien de lui-même), mais chaque pose est
// enregistrée : le témoin 15 juge celle de l'amorçage du lexique (cible, options, rappel).
const observateursPoses = [];
const fenetre = {
  document,
  localStorage: stockage(),
  sessionStorage: stockage(),
  location: { hash: "", pathname: "/", search: "", href: "http://plume.invalid/", origin: "http://plume.invalid", host: "plume.invalid", hostname: "plume.invalid", protocol: "http:", reload() {}, replace() {}, assign() {} },
  history: { pushState() {}, replaceState() {}, back() {}, state: null },
  navigator: { language: "fr-FR", userAgent: "harnais", clipboard: { writeText: async () => {} }, onLine: true },
  matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
  getComputedStyle: () => ({ getPropertyValue: () => "" }),
  requestAnimationFrame: (f) => setTimeout(f, 0),
  cancelAnimationFrame: (h) => clearTimeout(h),
  addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
  innerWidth: 1280, innerHeight: 800, devicePixelRatio: 1, scrollY: 0,
  scrollTo() {}, alert() {}, confirm: () => false, prompt: () => null, open() { return null; }, print() {},
  HTMLElement: Element, Element, Node: Element, Image: Element,
  MutationObserver: class { constructor(rappel) { this.rappel = rappel; } observe(cible, options) { observateursPoses.push({ rappel: this.rappel, cible, options }); } disconnect() {} },
  ResizeObserver: class { observe() {} disconnect() {} unobserve() {} },
  IntersectionObserver: class { observe() {} disconnect() {} unobserve() {} },
  EventSource: class { constructor() { this.readyState = 0; } close() {} addEventListener() {} },
  WebSocket: class { constructor() { this.readyState = 0; } close() {} addEventListener() {} send() {} },
  // Réseau : absent par construction. Voir l'en-tête : cette absence ne REFUSE pas un appel au
  // chargement d'un module, elle le fait seulement échouer.
  fetch: undefined,
};
for (const [k, v] of Object.entries(fenetre)) Object.defineProperty(globalThis, k, { value: v, writable: true, configurable: true });
globalThis.window = globalThis;
globalThis.self = globalThis;
// `P4.13-a` (reprise) — MODE « LE NAVIGATEUR REFUSE LE STOCKAGE DE SITE ».
// Un navigateur qui bloque le stockage de site (Chrome « bloquer tous les cookies » sur l'origine,
// contextes durcis, profils d'entreprise) ne rend PAS `null` : l'ACCÈS à `window.localStorage` JETTE
// `SecurityError`. Quatre lectures du dépôt s'exécutaient à l'ÉVALUATION de `state.js` et de `core.js` —
// la racine du graphe — donc avant tout `catch` applicatif : le graphe ES ne se liait pas et l'écran de
// connexion n'apparaissait jamais. Depuis `P4.13-a`, ce chemin est atteignable par un ANONYME.
// Le mode est porté par l'ENVIRONNEMENT et non par un second banc : c'est le MÊME simulacre, les MÊMES
// modules, la même section 1 — seule la propriété d'accès change. Le banc se relance LUI-MÊME dans ce
// mode (voir la section 1bis) plutôt que de réimporter les modules en double dans ce processus, ce qui
// rejouerait tous leurs effets de bord et fausserait les témoins qui comptent des poses.
const STOCKAGE_REFUSE = process.env.PLUME_HARNAIS_STOCKAGE_REFUSE === "1";
if (STOCKAGE_REFUSE) {
  const refus = () => { const e = new Error("Access to storage is not allowed from this context."); e.name = "SecurityError"; throw e; };
  for (const cle of ["localStorage", "sessionStorage"]) {
    Object.defineProperty(globalThis, cle, { get: refus, set: () => {}, configurable: true });
  }
}

// Le texte d'un sous-arbre, tel qu'un lecteur le verrait (sans mise en page).
const texte = (el) => el.textContent;

// ---------------------------------------------------------------------------------------------
// LE DOCUMENT DE LA PAGE (`P11.13-e`). Le shim ne portait AUCUN arbre : `querySelector` rendait un
// nœud détaché neuf à chaque appel et `querySelectorAll` une liste vide. Trois conséquences, toutes
// mesurées le 2026-08-25 : le changement de vue n'y masquait rien (`showView` itère sur
// `main > section`), tout paraissait donc AFFICHÉ, et la propriété « une charge ne part que si sa
// cible est visible » (`P11.17-a`) n'était pas gardable — un témoin l'aurait toujours trouvée vraie.
//
// CE QUI EST CONSTRUIT : l'arbre RÉEL de `index.html`, ancêtres compris, avec `id`, `hidden`, classes
// et la valeur sélectionnée des listes déroulantes. La page est la SOURCE ; rien n'est énuméré ici.
// CE QUI RESTE UN MENSONGE ASSUMÉ, et qui est écrit plutôt que tu : un identifiant ABSENT de la page
// rend encore un nœud détaché — mémoïsé, donc le même à chaque appel, comme le ferait un document —
// au lieu de `null`. Le rendre nul arrêterait au chargement tout module qui câble `$('#x').onclick`,
// et c'est le compromis que ce harnais assume depuis l'origine. Il est SANS EFFET sur la visibilité :
// un nœud hors page n'a pas d'ancêtre masqué, donc une charge qui viserait un identifiant inexistant
// serait comptée affichée — c'est pourquoi le témoin de couverture lit la page, jamais le registre.
// ---------------------------------------------------------------------------------------------
const VIDES = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
  "path", "circle", "rect", "line", "polyline", "polygon", "use", "stop", "ellipse", "feoffset", "fegaussianblur", "femerge", "femergenode"]);
const OPAQUES = new Set(["script", "style", "textarea"]);
const parIdentifiant = new Map();
let mainDeLaPage = null;
// Les entités que la page et les modules écrivent réellement ; le reste passe par le point de code.
const ENTITES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: "\u00a0", times: "\u00d7", hellip: "…", mdash: "—", ndash: "–", laquo: "«", raquo: "»", rsquo: "’", lsquo: "‘", ldquo: "“", rdquo: "”", middot: "·", bull: "•", deg: "°", copy: "©", reg: "®", larr: "←", rarr: "→", harr: "↔", check: "✓" };
const decoder = (t) => (t.indexOf("&") < 0 ? t : t.replace(/&(#[xX]?[0-9a-fA-F]+|[a-zA-Z]+);/g, (brut, c) => {
  if (c[0] !== "#") return ENTITES[c] ?? brut;
  const n = c[1] === "x" || c[1] === "X" ? parseInt(c.slice(2), 16) : parseInt(c.slice(1), 10);
  return Number.isFinite(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : brut;
}));

// `P11.13-g` — LE BALISAGE POSÉ EN BLOC EST ANALYSÉ. Ce lecteur ne servait qu'à la page ; `innerHTML`,
// lui, ne faisait que RETENIR LA CHAÎNE, si bien qu'un sous-arbre posé en bloc n'existait pas : une
// recherche dedans rendait le nœud de repli, son texte était vide, et ses attributs de données étaient
// introuvables. Mesuré le 2026-08-25 : 31 sélecteurs distincts n'étaient pas résolus dans le banc, dont
// la quasi-totalité visait un contenu posé de cette façon (la boîte modale partagée, la palette d'un
// panneau, la barre des alertes). Le même lecteur sert donc les deux, avec les NŒUDS TEXTE — sans eux
// le texte d'un bloc posé ainsi restait invisible, ce qui est le défaut mesuré.
function analyserBalisage(html, racine, page) {
  const pile = [racine];
  const RE = /<!--[\s\S]*?-->|<(\/?)([a-zA-Z][\w:-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)(\/?)>/g;
  const neufs = [];
  let m, curseur = 0;
  const jusqua = (fin) => { const brut = html.slice(curseur, fin); if (brut) pile[pile.length - 1].appendChild(new Text(decoder(brut))); };
  while ((m = RE.exec(html))) {
    jusqua(m.index);
    curseur = RE.lastIndex;
    if (m[0].startsWith("<!--")) continue;
    const fermante = m[1] === "/", tag = m[2].toLowerCase(), attrs = m[3] || "", autoferme = m[4] === "/";
    if (fermante) { if (pile.length > 1 && pile[pile.length - 1].tagName === tag.toUpperCase()) pile.pop(); continue; }
    const el = new Element(tag);
    for (const a of attrs.matchAll(/([\w:-]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
      const nom = a[1].toLowerCase(), val = decoder(a[3] ?? a[4] ?? a[5] ?? "");
      if (nom === "id") el.id = val;
      else if (nom === "class") el.className = val;
      else if (nom === "hidden") el.hidden = true;
      else el.setAttribute(nom, val);
    }
    pile[pile.length - 1].appendChild(el);
    neufs.push(el);
    if (page) {
      if (tag === "main" && !mainDeLaPage) mainDeLaPage = el;
      // Le raccourci par identifiant n'indexe QUE la page : un identifiant posé plus tard par un module
      // se retrouve par parcours, donc rien ne devient introuvable — seulement moins rapide.
      if (el.id && !parIdentifiant.has(el.id)) parIdentifiant.set(el.id, el);
    }
    // Un élément OPAQUE EXISTE dans le document — seul son CONTENU est ignoré. Le sauter entièrement
    // le faisait DISPARAÎTRE : l'éditeur de requête est un `<textarea>`, sa cible était introuvable et
    // toute dérivation qui le lit (la barre de recherche de l'en-tête, la section d'une charge)
    // répondait « nulle part ». Mesuré le 2026-08-25 en écrivant le témoin de couverture.
    if (OPAQUES.has(tag)) { const fin = html.indexOf("</" + tag, RE.lastIndex); if (fin >= 0) { RE.lastIndex = fin; curseur = fin; } continue; }
    if (!VIDES.has(tag) && !autoferme) pile.push(el);
  }
  jusqua(html.length);
  // Une liste déroulante porte la valeur de son option `selected` : sans elle, la cadence par défaut
  // de la console (le `selected` du balisage) serait lue comme vide et rien ne s'armerait.
  for (const el of neufs) {
    if (el.tagName !== "SELECT") continue;
    el.options = el.children.filter((c) => c.tagName === "OPTION");
    const choisie = el.options.find((o) => o.hasAttribute("selected")) || el.options[0];
    if (choisie) { el.value = choisie.getAttribute("value") ?? choisie.textContent; el.selectedIndex = el.options.indexOf(choisie); }
    if (el.hasAttribute("value")) el.value = el.getAttribute("value");
  }
  return neufs;
}
analyserBalisage(readFileSync(path.join(WEB, "index.html"), "utf8"), document.body, true);
const sectionsDeLaPage = () => (mainDeLaPage ? mainDeLaPage.children.filter((c) => c.tagName === "SECTION") : []);
// UN MOTEUR DE SÉLECTEURS MINIMAL — tag, identifiant, classes, attributs, descendant, enfant direct,
// `:scope`, listes séparées par des virgules. Il ne prétend pas être CSS ; il couvre ce que la console
// écrit. IL EST DEVENU NÉCESSAIRE EN FERMANT L'AUTRE TROU : tant que l'insertion ne détachait pas, un
// sélecteur non résolu rendait un nœud détaché sans conséquence. Depuis que détacher est fidèle, un
// `main.appendChild(section)` résolu vers un faux `main` ARRACHE la section du document — mesuré le
// 2026-08-25 : le réordonnancement des cartes de la Vue d'ensemble sortait les quatre du document et
// la vue paraissait n'avoir aucune charge. Les deux trous ne se ferment donc pas séparément.
const RE_ETAPE = /^([a-zA-Z][\w-]*)?(#[\w-]+)?((?:\.[\w-]+)*)((?:\[[^\]]+\])*)$/;
// `P11.15-a` — UNE ÉTAPE QUE LE MOTEUR NE SAIT PAS LIRE RENDAIT « AUCUN NŒUD », ET C'EST UN VERDICT.
// Mesuré le 2026-08-26 : `:not(…)` ne passe pas `RE_ETAPE`, donc `etapeCorrespond` rendait faux pour
// TOUT élément, donc `querySelectorAll` rendait une liste VIDE — silencieusement. Le seul sélecteur de
// `web/` qui l'emploie est celui de la fabrique de tableaux (`tbody > tr:not(.rowdetail) > td`, deux
// sites, `core.js`) : le mécanisme de dépli de cellule ne pouvait donc RIEN trouver ici, et un banc qui
// rend « 0 cellule » là où il y en a huit dit une absence qu'il n'a pas mesurée. L'exclusion est retirée
// de l'étape AVANT la lecture, puis rejouée par la même fonction sur ce qu'elle exclut : une seule
// grammaire, dans les deux sens. Une étape restée illisible rend toujours faux — c'est la limite, et le
// témoin 41 l'épingle en exigeant que l'exclusion RETIRE des nœuds au lieu de tous les emporter.
const RE_NON = /:not\(([^()]*)\)/g;
function etapeCorrespond(el, etape) {
  const exclusions = [];
  const base = String(etape).replace(RE_NON, (_, dedans) => { exclusions.push(String(dedans).trim()); return ""; });
  const m = RE_ETAPE.exec(base);
  if (!m || !el.tagName) return false;
  for (const ex of exclusions) if (ex && ex.split(",").some((b) => etapeCorrespond(el, b.trim()))) return false;
  if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
  if (m[2] && el.id !== m[2].slice(1)) return false;
  for (const c of (m[3] || "").split(".").filter(Boolean)) if (!el.classList.contains(c)) return false;
  for (const a of (m[4] || "").match(/\[[^\]]+\]/g) || []) {
    const mm = /^\[([\w:-]+)(?:=["']?([^\]"']*)["']?)?\]$/.exec(a);
    if (!mm) return false;
    const v = el.getAttribute(mm[1]);
    if (v === null || (mm[2] !== undefined && v !== mm[2])) return false;
  }
  return true;
}
function descendants(n, sortie) {
  for (const c of n.children || []) { if (c.tagName) { sortie.push(c); descendants(c, sortie); } }
  return sortie;
}
function chercher(racine, sel, tous) {
  const out = [];
  for (const brut of String(sel).split(",")) {
    const etapes = brut.trim().split(/\s*(>)\s*|\s+/).filter(Boolean);
    if (!etapes.length) continue;
    let courants = [racine], direct = false, premiere = true;
    for (const e of etapes) {
      if (e === ">") { direct = true; continue; }
      if (e === ":scope") { premiere = false; continue; }
      // Raccourci par identifiant : la page en compte des centaines, un parcours complet par requête
      // rendrait le harnais inutilisable.
      const parId = premiere && !direct && /^[a-zA-Z]*#[\w-]+/.test(e) ? parIdentifiant.get(e.match(/#([\w-]+)/)[1]) : null;
      if (parId) { courants = etapeCorrespond(parId, e) && racine.contains(parId) ? [parId] : []; premiere = false; continue; }
      const suiv = [];
      for (const n of courants) for (const c of (direct ? (n.children || []).filter((x) => x.tagName) : descendants(n, []))) {
        if (etapeCorrespond(c, e) && !suiv.includes(c)) suiv.push(c);
      }
      courants = suiv; direct = false; premiere = false;
    }
    for (const c of courants) if (!out.includes(c)) out.push(c);
    if (!tous && out.length) break;
  }
  return out;
}
// `P11.13-g` — CE QUI N'EXISTE PAS REND `null`. Le shim rendait un nœud détaché — mémoïsé, portant même
// l'identifiant demandé — au motif qu'un module qui câble `$('#x').onclick` s'arrêterait autrement au
// chargement. LE MOTIF A ÉTÉ MESURÉ ET RÉFUTÉ le 2026-08-25 : avec `null`, les 49 modules de `web/` se
// lient encore, zéro échec. Le prix du mensonge, lui, était réel — toute garde de pose de la forme
// « si l'élément est déjà là, ne rien faire » répondait OUI, sur un nœud que personne n'avait posé.
function unSeul(racine, sel) {
  const t = chercher(racine, sel, false);
  return t.length ? t[0] : null;
}
document.querySelector = (sel) => unSeul(document.body, sel);
document.getElementById = (id) => unSeul(document.body, "#" + id);
document.querySelectorAll = (sel) => chercher(document.body, sel, true);
Element.prototype.querySelector = function (sel) { return unSeul(this, sel); };
Element.prototype.querySelectorAll = function (sel) { return chercher(this, sel, true); };

// ---------------------------------------------------------------------------------------------
// MODE « UNE SEULE ENTRÉE » (`P11.21-f`). Ouvrir le graphe de modules par UNE porte, et RIEN d'autre.
//
// POURQUOI UN PROCESSUS ENTIER POUR UN SEUL IMPORT. La section 1 importe les 49 modules dans le MÊME
// processus : dès la première entrée, le graphe est en cache, et « ce module se charge » ne dit plus
// rien de ce qui arrive à qui l'ouvre EN PREMIER. Un registre de modules ne se vide pas ; la seule
// façon d'obtenir une évaluation NEUVE est un processus neuf. Ce mode est donc l'enfant que la
// section 1-a relance une fois par module.
//
// IL EST POSÉ ICI, juste après le simulacre de document et AVANT la première section : l'enfant paie
// le simulacre — que les modules exigent pour s'évaluer — et l'import mesuré, rien d'autre. Aucun
// témoin ne s'exécute entre les deux, donc rien du banc ne peut peser sur ce qui est mesuré.
//
// TROIS ISSUES DISTINCTES, et c'est ce qui sépare une mesure d'un accident : `0` = le module s'est
// chargé, `3` = il a JETÉ (la ligne rendue sur la sortie d'erreur porte le type, le message et le
// SITE de premier niveau — la ligne à corriger, qui n'est presque jamais dans le module par lequel on
// est entré), tout autre code = l'enfant est mort d'autre chose et l'appelant REFUSE de conclure.
// ---------------------------------------------------------------------------------------------
const UNE_ENTREE = process.env.PLUME_HARNAIS_UNE_ENTREE;
if (UNE_ENTREE) {
  try {
    await import(pathToFileURL(UNE_ENTREE).href);
    process.exit(0);
  } catch (e) {
    // Le cadre de PREMIER NIVEAU est le seul de la pile qui n'a pas de nom de fonction : c'est le corps
    // d'un module en cours d'évaluation. Les cadres nommés, eux, désignent la fonction appelée, pas le
    // site qui l'appelle — or c'est le site qu'il faut corriger.
    const pile = String((e && e.stack) || "");
    const site = (pile.match(/^\s*at (file:\/\/\S+?:\d+:\d+)$/m) || [])[1] || "(aucun cadre de premier niveau dans la pile)";
    process.stderr.write(`${(e && e.name) || "(sans type)"}|${String((e && e.message) || "").split("\n")[0]}|${site}\n`);
    process.exit(3);
  }
}


// Le plancher de découverte, partagé par la déclaration (section 0) et par la liaison (section 1) :
// une seule valeur, pour que les deux refusent de conclure sur le même corpus amputé.
const PLANCHER_MODULES = 20;
const echecs = [];
const exiger = (cond, msg) => { if (!cond) echecs.push(msg); };

// ---------------------------------------------------------------------------------------------
// 0. CE QUE CE BANC NE TIENT PAS — ÉTABLI PAR SONDAGE, JAMAIS RECOPIÉ (`P11.13-g`).
//
//    Un banc dont le vert se lit comme une COUVERTURE ment exactement comme une grandeur illisible
//    rendue « 0 » : c'est le défaut que ce dépôt refuse au produit, et il n'a pas à se le permettre.
//    Une PHRASE écrite à la main ne suffirait pas — elle vieillirait mal, et un trou fermé y resterait
//    déclaré ouvert (ou l'inverse, ce qui est pire). La déclaration est donc DÉRIVÉE : chaque capacité
//    est EXERCÉE sur le simulacre, et ce qu'elle rend décide de sa place dans le verdict.
//
//    L'INSTRUMENT SE VALIDE DANS LES DEUX SENS, capacité par capacité. Une sonde qui ne distinguerait
//    pas une implémentation qui TIENT d'une qui ne tient pas ne mesurerait rien : chaque capacité porte
//    donc son témoin POSITIF (une implémentation minimale, écrite à la main, qui la tient) et son
//    témoin NÉGATIF (celle d'avant). Une sonde muette est un ÉCHEC, pas une capacité « non tenue ».
//
//    ET LE POIDS DE CHAQUE LIMITE EST MESURÉ SUR `web/`, pas supposé : le nombre de sites du corpus
//    qui en dépendent est compté le jour même. Une capacité dont AUCUN site ne dépend n'a pas à figurer
//    dans un aveu — elle serait du bruit ; le compteur de corpus est lui aussi validé aux deux bouts.
// ---------------------------------------------------------------------------------------------
const CORPUS_WEB = readdirSync(WEB).filter((f) => /\.(js|css|html)$/.test(f) && f !== "sw.js")
  .map((f) => [f, readFileSync(path.join(WEB, f), "utf8")]);
const sitesDansWeb = (motif, ext) => CORPUS_WEB.filter(([f]) => f.endsWith(ext)).reduce((n, [, src]) => n + (src.match(motif) || []).length, 0);

// Le corpus AVANT tout ce qu'on en tire : un compteur qui ne trouve rien ne prouve pas une absence, il
// prouve peut-être qu'il lit le vide. Témoin positif ET négatif, plus le plancher de fichiers.
const JS_DU_CORPUS = CORPUS_WEB.filter(([f]) => f.endsWith(".js")).length;
exiger(JS_DU_CORPUS >= PLANCHER_MODULES, `(0-instrument) ${JS_DU_CORPUS} module(s) JS dans le corpus lu, plancher ${PLANCHER_MODULES} : la lecture de web/ est cassée, aucun poids de limite ne veut rien dire`);
exiger(sitesDansWeb(/function/g, ".js") > 0, "(0-instrument) le compteur de corpus ne trouve pas même le mot `function` dans web/*.js : il lit le vide, et un zéro de sa part ne prouverait aucune absence");
exiger(sitesDansWeb(/zzz-motif-qui-n-existe-pas-zzz/g, ".js") === 0, "(0-instrument) le compteur de corpus trouve un motif inexistant : il compte n'importe quoi, et un compte de sa part ne mesure rien");

// Chaque capacité : ce qu'elle tient, la sonde qui l'exerce, l'implémentation minimale qui la TIENT,
// celle d'AVANT qui ne la tient pas, le motif qui en mesure le poids sur `web/`, et la conséquence
// d'une réponse fausse — écrite ici parce qu'elle est la RAISON d'être de l'aveu.
const CAPACITES = [
  {
    nom: "la mise en page",
    tient: "une largeur, une hauteur, un débordement",
    sonde: (env) => { const el = env.creer("div"); el.textContent = "un texte bien plus long que la cellule qui le porte"; const r = el.getBoundingClientRect ? el.getBoundingClientRect() : null; return (el.scrollWidth > 0) || (el.offsetWidth > 0) || !!(r && r.width > 0); },
    tenu: () => ({ creer: () => ({ textContent: "", scrollWidth: 320, offsetWidth: 320, getBoundingClientRect: () => ({ width: 320, height: 18 }) }) }),
    nu: () => ({ creer: () => ({ textContent: "", getBoundingClientRect: () => ({ width: 0, height: 0 }) }) }),
    motif: /getBoundingClientRect|offset(?:Width|Height|Parent)|scroll(?:Width|Height)|client(?:Width|Height)/g, ext: ".js",
    consequence: "le prédicat « cette cellule déborde » y vaut TOUJOURS faux, de sorte qu'un mécanisme entier de dépli passe sans être exercé et qu'un défaut peint à l'écran rend VERT",
  },
  {
    nom: "le style calculé",
    tient: "ce qu'une feuille de style impose réellement — masquage, couleur, encre peinte",
    sonde: (env) => env.calcule(env.creer("div")).getPropertyValue("display") !== "",
    tenu: () => ({ creer: () => ({}), calcule: () => ({ getPropertyValue: () => "none" }) }),
    nu: () => ({ creer: () => ({}), calcule: () => ({ getPropertyValue: () => "" }) }),
    motif: /\{/g, ext: ".css",
    consequence: "un masquage, une troncature ou une couleur imposés par la feuille de style sont invisibles ici — seul l'attribut du document est lu ; la preuve passe alors par un vrai moteur de rendu",
  },
  {
    nom: "le chemin d'un événement",
    tient: "qu'un écouteur POSÉ soit rappelé, avec sa cible, en capture puis en remontée",
    sonde: (env) => { const parent = env.creer("div"), enfant = env.creer("button"); parent.appendChild(enfant); let vu = null; parent.addEventListener("click", (e) => { vu = e && e.target; }); enfant.click(); return vu === enfant; },
    tenu: () => { const faire = () => { const n = { _l: [], enfants: [], parent: null, appendChild(c) { c.parent = this; this.enfants.push(c); return c; }, addEventListener(t, f) { this._l.push([t, f]); }, click() { const ev = { type: "click", target: this }; for (let p = this; p; p = p.parent) p._l.filter(([t]) => t === "click").forEach(([, f]) => f(ev)); } }; return n; }; return { creer: faire }; },
    nu: () => ({ creer: () => ({ appendChild(c) { return c; }, addEventListener() {}, click() {}, dispatchEvent() { return true; } }) }),
    motif: /addEventListener|\.onclick\s*=|\.click\(\)/g, ext: ".js",
    consequence: "POSER un écouteur ne prouve rien du chemin réel de la frappe — c'est ce qui a failli valider une recherche NON FONCTIONNELLE",
  },
  {
    nom: "l'attribut `disabled`",
    tient: "qu'un contrôle inerte se lise comme tel, par l'attribut et par le sélecteur",
    sonde: (env) => { const b = env.creer("button"); b.disabled = true; if (!b.hasAttribute("disabled")) return false; b.disabled = false; return !b.hasAttribute("disabled"); },
    tenu: () => ({ creer: () => ({ _a: {}, set disabled(v) { if (v) this._a.disabled = ""; else delete this._a.disabled; }, get disabled() { return "disabled" in this._a; }, hasAttribute(k) { return k in this._a; } }) }),
    nu: () => ({ creer: () => ({ hasAttribute: () => false }) }),
    motif: /\.disabled\b|\bdisabled\b/g, ext: ".js",
    consequence: "un geste qui S'ANNULE LUI-MÊME sans un mot reste invisible — c'est la régression réelle à laquelle ce banc a été aveugle",
  },
  {
    nom: "le balisage posé en bloc",
    tient: "qu'un sous-arbre posé d'un coup EXISTE : on l'y cherche, on y lit son texte et ses attributs",
    sonde: (env) => { const h = env.creer("div"); h.innerHTML = '<span class="marque" data-act="go">Bonjour</span>'; const t = h.querySelector(".marque"); return !!t && t.tagName === "SPAN" && String(h.textContent).includes("Bonjour"); },
    tenu: () => ({ creer: () => ({ _n: null, set innerHTML(v) { this._n = { tagName: "SPAN", texte: "Bonjour" }; }, get textContent() { return this._n ? this._n.texte : ""; }, querySelector(sel) { return sel === ".marque" ? this._n : null; } }) }),
    nu: () => ({ creer: () => ({ _h: "", set innerHTML(v) { this._h = v; }, get textContent() { return ""; }, querySelector() { return { tagName: "DIV" }; } }) }),
    motif: /\.innerHTML\s*[+]?=|insertAdjacentHTML/g, ext: ".js",
    consequence: "une recherche dans un fragment rend un nœud de repli, son texte paraît vide, et ce qu'un module vient de peindre n'est jugé par personne",
  },
  {
    nom: "l'absence d'un identifiant",
    tient: "qu'un identifiant ABSENT rende `null` — et qu'un identifiant PRÉSENT rende son élément",
    // CONTRÔLE POSITIF DANS LA SONDE MÊME : sans la seconde moitié, un document qui ne rendrait JAMAIS
    // rien passerait pour fidèle. « Absent » et « invisible à cet instrument » ne se distinguent pas
    // autrement — c'est la faute d'instrument qui est revenue cinq fois dans la journée.
    sonde: (env) => env.doc.getElementById("cet-identifiant-n-existe-nulle-part") === null && !!env.doc.getElementById(env.present),
    tenu: () => ({ doc: { getElementById: (id) => (id === "vrai" ? { tagName: "DIV" } : null) }, present: "vrai" }),
    nu: () => ({ doc: { getElementById: (id) => ({ tagName: "DIV", id }) }, present: "vrai" }),
    motif: /getElementById|querySelector\(\s*[`'"]#/g, ext: ".js",
    consequence: "toute garde de pose de la forme « si c'est déjà là, ne rien faire » répond OUI, sur un nœud que personne n'a posé",
  },
  {
    nom: "les attributs de données",
    tient: "que `dataset` et `data-*` soient la MÊME donnée, dans les deux sens",
    sonde: (env) => { const el = env.creer("i"); el.dataset.acLie = "1"; if (el.getAttribute("data-ac-lie") !== "1") return false; el.setAttribute("data-role", "ligne"); return el.dataset.role === "ligne"; },
    tenu: () => ({ creer: () => { const a = {}; return { attributs: a, dataset: { set acLie(v) { a["data-ac-lie"] = String(v); }, get role() { return a["data-role"]; } }, getAttribute: (k) => a[k] ?? null, setAttribute: (k, v) => { a[k] = String(v); } }; } }),
    nu: () => ({ creer: () => ({ dataset: {}, getAttribute: () => null, setAttribute() {} }) }),
    motif: /\.dataset\b|data-[a-z-]+\s*=/g, ext: ".js",
    consequence: "un palier cliqué pose une valeur INDÉFINIE, et le sélecteur `[data-…]` — le câblage de délégation le plus employé de la console — ne trouve jamais ce que le code vient d'écrire",
  },
];

// Le simulacre RÉEL, capacité par capacité. Le seul environnement qui n'est pas fabriqué ici.
const UN_ID_DE_LA_PAGE = [...parIdentifiant.keys()][0];
exiger(typeof UN_ID_DE_LA_PAGE === "string", "(0-instrument) la page ne porte AUCUN identifiant : le contrôle positif de l'absence n'a pas de contre-exemple, la sonde refuse de conclure");
const SIMULACRE = { creer: (t) => document.createElement(t), calcule: (el) => getComputedStyle(el), doc: document, present: UN_ID_DE_LA_PAGE };

for (const c of CAPACITES) {
  const surTenu = c.sonde(c.tenu()), surNu = c.sonde(c.nu());
  exiger(surTenu === true && surNu === false,
    `(0-instrument) la sonde « ${c.nom} » ne distingue pas une implémentation qui TIENT (${surTenu}) d'une qui ne tient pas (${surNu}) : son verdict sur le simulacre ne mesurerait rien, et l'aveu qui en dérive serait faux`);
  c.verdict = c.sonde(SIMULACRE) === true;
  c.sites = sitesDansWeb(c.motif, c.ext);
  exiger(c.sites > 0, `(0-instrument) aucun site de web/*${c.ext} ne dépend de « ${c.nom} » : le motif ne mesure plus rien (déplacé, renommé) et le poids de cette limite serait faux`);
}

// LA DÉRIVATION EST-ELLE UNE DÉRIVATION ? MUTATION : la MÊME fonction, appliquée à un simulacre
// entièrement nu puis à un simulacre entièrement fidèle, doit rendre TOUTES les capacités puis AUCUNE.
// Une liste écrite en dur rendrait la même chose trois fois — et c'est précisément ce qu'on refuse.
const limitesDe = (choix) => CAPACITES.filter((c) => c.sonde(choix(c)) !== true);
exiger(limitesDe((c) => c.nu()).length === CAPACITES.length, `(0) la dérivation ne voit pas les ${CAPACITES.length} capacités d'un simulacre entièrement nu : elle ne dérive de rien`);
exiger(limitesDe((c) => c.tenu()).length === 0, "(0) la dérivation déclare une limite sur un simulacre qui tient TOUT : l'aveu serait une constante, pas une mesure");

const LIMITES = CAPACITES.filter((c) => !c.verdict);
const TENUES = CAPACITES.filter((c) => c.verdict);
const AVEU = LIMITES.length
  // `P11.15-a` — LA CLAUSE DE FIN A ÉTÉ CORRIGÉE PARCE QU'ELLE EST DEVENUE FAUSSE. Elle disait « aucun
  // n'est exercé ici » ; le témoin 41 exerce désormais les deux sites du prédicat de débordement, sur des
  // largeurs qu'il POSE lui-même. Ce qui reste vrai, et qui est la seule chose que la section 0 mesure :
  // le simulacre ne MESURE aucune de ces capacités — un témoin qui en a besoin doit la fabriquer, et il ne
  // juge alors que le code qui la consomme, jamais le résultat peint.
  ? LIMITES.map((c) => `${c.nom} (${c.tient}) — ${c.consequence} ; ${c.sites} site(s) de web/*${c.ext} en dépendent et le simulacre n'en mesure AUCUN : un témoin qui a besoin de cette capacité doit poser la mesure lui-même, et il ne juge alors que le code qui la consomme`).join("\n  · ")
  : "rien de ce qui est sondé — les " + CAPACITES.length + " capacités mesurées sont tenues";
console.log(`[simulacre] ${CAPACITES.length} capacités SONDÉES sur le shim, chacune validée dans les deux sens (témoin positif + témoin négatif) : ${TENUES.length} tenue(s) — ${TENUES.map((c) => c.nom).join(", ") || "aucune"} ; ${LIMITES.length} NON tenue(s) — ${LIMITES.map((c) => c.nom).join(", ") || "aucune"}.`);
if (LIMITES.length) console.log(`[simulacre] CE QUE LE VERT DE CE BANC NE DIT PAS :\n  · ${AVEU}`);

// UN BANC QUI MEURT DOIT DIRE CE QU'IL AVAIT DÉJÀ TROUVÉ. Les témoins en échec ne sont imprimés qu'au
// verdict : une exception en cours de route les emportait tous en silence, et il ne restait qu'une pile
// d'appels — c'est-à-dire l'inverse de ce que cette clé demande. Armé ICI, au plus tôt.
let verdictRendu = false;
process.on("exit", (code) => {
  if (verdictRendu || code === 0) return;
  console.error(`\n[interrompu] le banc s'est arrêté avant son verdict (code ${code}). ${echecs.length} témoin(s) étaient DÉJÀ en échec :`);
  for (const e of echecs) console.error(`::error::${e}`);
  console.error(`\nCE QUE CE BANC NE TIENT PAS, quoi qu'il arrive ensuite :\n  · ${AVEU}`);
});

// ---------------------------------------------------------------------------------------------
// 1. LE GRAPHE DE MODULES SE LIE — chaque module suivi de `web/`, sauf le service worker (il n'est
//    pas un module ES et lit des globales de son propre contexte).
// ---------------------------------------------------------------------------------------------
const modules = readdirSync(WEB).filter((f) => f.endsWith(".js") && f !== "sw.js").sort();

// ---------------------------------------------------------------------------------------------
// 1-a. LE GRAPHE S'OUVRE PAR N'IMPORTE QUELLE PORTE, ET PAS SEULEMENT PAR CELLE QUE LA PAGE EMPRUNTE
//      (`P11.21-f`). CE TÉMOIN MESURE, IL NE FERME PAS LA CLÉ.
//
//      LE TÉMOIN NAÏF SERAIT VERT PAR CONSTRUCTION, ET C'EST MESURÉ. La boucle de la section 1
//      ci-dessous importe tous les modules dans le MÊME processus : dès la première entrée, le graphe
//      est en cache et son verdict ne dépend plus que de l'ordre du répertoire. Mesuré le 2026-08-30,
//      MÊME corpus, MÊME processus, seul l'ordre changeant : l'ordre alphabétique perd ZÉRO module sur
//      49 ; entrer par `attack.js`, par `navigation.js` ou par `threatintel.js` en perd VINGT-TROIS —
//      et c'est EXACTEMENT le même ensemble de 23 aux trois portes, ce qui dit bien que ce qu'on mesure
//      alors n'est pas « ce module est sain » mais « le cache a été empoisonné par la première entrée ».
//      Un registre de modules ne se vide pas : la propriété ne se mesure QUE dans un processus NEUF par
//      entrée — et c'est ce que
//      le mode « une seule entrée » (posé plus haut, juste après le simulacre) rend possible.
//
//      LA SONDE EST POSÉE AVANT LA BOUCLE, ET CET ORDRE EST LA PROPRIÉTÉ. Posée après, elle mesurerait
//      un processus dont le graphe est déjà chargé — c'est-à-dire rien.
//
//      LE DÉFAUT EST LATENT, ET IL EST DIT : la page servie n'ouvre le graphe que par `app.js`
//      (`index.html` ne porte qu'un seul `<script type="module">`), donc rien n'est cassé à l'écran.
//      Ce qui est mesuré ici est la portabilité du graphe : un second point d'entrée — un module
//      chargé à la demande, un banc, un outil — le rencontrerait le jour où il l'ouvre.
//
//      CE TÉMOIN NE PROPOSE PAS DE CORRECTIF, et c'est délibéré : déplacer l'appel d'amorçage
//      fautif hors de la colonne 1, ou l'envelopper dans une attente, a été FABRIQUÉ, JOUÉ et REFUSÉ
//      par le témoin (53c) de ce même banc, qui exige que l'appel d'amorçage reste en colonne 1 d'un
//      corps SYNCHRONE — sans quoi « la densité est posée avant la première peinture » devient faux
//      en silence. Les deux propriétés ne se satisfont pas par un déplacement de ligne.
// ---------------------------------------------------------------------------------------------
if (!STOCKAGE_REFUSE) {
  const { spawnSync } = await import("node:child_process");
  const { tmpdir } = await import("node:os");
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const MOI = new URL(import.meta.url).pathname;

  // Une entrée, un processus NEUF. L'environnement est NETTOYÉ des deux autres modes du banc : hériter
  // de `…_STOCKAGE_REFUSE` ferait mesurer un simulacre différent de celui qu'on prétend mesurer.
  const ouvrirLeGraphePar = (chemin) => {
    const env = { ...process.env, PLUME_HARNAIS_UNE_ENTREE: chemin };
    delete env.PLUME_HARNAIS_STOCKAGE_REFUSE;
    const r = spawnSync(process.execPath, [MOI], { env, encoding: "utf8" });
    const derniere = String(r.stderr || "").trim().split("\n").pop();
    const [type, message, site] = derniere.split("|");
    return { code: r.status, type, message, site, brut: `${r.stdout || ""}${r.stderr || ""}`.slice(0, 800) };
  };

  // ------ L'INSTRUMENT SE VALIDE SUR DES MODULES FABRIQUÉS, DANS LES DEUX SENS ------
  // Sur le dépôt, une sonde qui ne verrait JAMAIS rien serait verte, et une sonde qui verrait TOUJOURS
  // un échec ne le serait pas — mais aucune des deux ne serait distinguable de la bonne tant qu'on la
  // juge sur le seul corpus mesuré. Les trois modules ci-dessous sont écrits ICI, hors du dépôt : le
  // verdict de la sonde sur eux ne dépend d'aucun état du dépôt, donc il ne peut pas devenir une RANÇON.
  // UN `finally` NE SURVIT PAS À UN SIGNAL, ET C'EST MESURÉ (`P8.9-p`, le 2026-08-30). Le retrait
  // ci-dessous vit dans un `finally` : il s'exécute sur un passage VERT comme sur un passage ROUGE —
  // les deux vérifiés, zéro résidu. Mais un SIGTERM tue le processus AVANT lui, et six bacs traînaient
  // dans le répertoire temporaire, laissés par des passages interrompus. Ce n'est pas le `finally` qui
  // est mal écrit : c'est qu'AUCUNE discipline de nettoyage écrite dans le corps ne survit à un signal.
  // Le crochet ci-dessous ferme le chemin du signal, et rien d'autre — un SIGKILL restera hors de portée,
  // ce qui est dit ici plutôt que laissé croire.
  const bac = mkdtempSync(path.join(tmpdir(), "plume-harnais-p11-21-f-"));
  const balayerLeBac = () => { try { rmSync(bac, { recursive: true, force: true }); } catch { /* déjà retiré */ } };
  const surSignal = (sig) => { balayerLeBac(); process.removeListener(sig, surSignal); process.kill(process.pid, sig); };
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"]) process.once(sig, () => surSignal(sig));
  try {
    // (+) LE POSITIF. Sans lui, un vert de cette sonde ne prouverait rien : un enfant qui ne chargerait
    //     jamais rien rendrait « tout jette », un enfant qui ne mesurerait rien rendrait « tout charge ».
    writeFileSync(path.join(bac, "sain.js"), "const TABLE = { a: 1 };\nexport function lire() { return TABLE.a; }\nexport const PRET = lire();\n");
    // (−) LE NÉGATIF REPRODUIT LA FORME DU DÉFAUT, PAS UNE ERREUR QUELCONQUE. Deux modules en CYCLE
    //     dont le corps de l'un appelle son partenaire EN COLONNE 1, avant que la constante que ce
    //     partenaire lit ne soit initialisée. Ce qui en sort est un `ReferenceError` d'ÉVALUATION
    //     (« Cannot access … before initialization »), PAS une `SyntaxError` d'ÉDITION DE LIENS : une
    //     sonde qui ne verrait que les erreurs de liaison — la seule chose que la boucle de la section 1
    //     sache voir — passerait à côté de tout ce défaut, et c'est EXIGÉ ci-dessous, pas supposé.
    writeFileSync(path.join(bac, "porte_fautive.js"), "import './partenaire.js';\nexport function poser() { return TABLE.a; }\nconst TABLE = { a: 1 };\n");
    writeFileSync(path.join(bac, "partenaire.js"), "import { poser } from './porte_fautive.js';\nposer();\n");

    const surSain = ouvrirLeGraphePar(path.join(bac, "sain.js"));
    const surFautive = ouvrirLeGraphePar(path.join(bac, "porte_fautive.js"));
    const surAutrePorte = ouvrirLeGraphePar(path.join(bac, "partenaire.js"));

    if (surSain.code !== 0) {
      console.error(`::error::(1a-instrument) un module FABRIQUÉ SANS DÉFAUT n'est pas vu se charger (code ${surSain.code}) : la sonde ne sait pas reconnaître un chargement, et son vert sur web/ ne prouverait rien. Sortie de l'enfant :\n${surSain.brut}`);
      process.exit(2);
    }
    if (surFautive.code !== 3) {
      console.error(`::error::(1a-instrument) le couple FABRIQUÉ en cycle — dont un corps appelle son partenaire en colonne 1 — n'est pas vu JETER par sa porte fautive (code ${surFautive.code} au lieu de 3) : la sonde ne mesure pas le défaut qu'elle prétend borner. Sortie de l'enfant :\n${surFautive.brut}`);
      process.exit(2);
    }
    if (surFautive.type !== "ReferenceError" || !/before initialization/.test(surFautive.message || "")) {
      console.error(`::error::(1a-instrument) le couple fabriqué jette bien, mais PAS DE LA FORME du défaut : « ${surFautive.type} — ${surFautive.message} » au lieu d'un \`ReferenceError\` d'évaluation. Une sonde qui ne verrait que les erreurs d'ÉDITION DE LIENS (\`SyntaxError\` : « does not provide an export named … ») ne mesurerait rien de ceci — c'est précisément ce que la boucle de la section 1 sait déjà voir, et ce témoin-ci n'existe que pour ce qu'elle ne voit pas.`);
      process.exit(2);
    }
    if (surAutrePorte.code !== 0) {
      console.error(`::error::(1a-instrument) le MÊME couple fabriqué, ouvert par son AUTRE porte, n'est pas vu se charger (code ${surAutrePorte.code}) : la sonde ne distingue pas une porte d'une autre. Or la dépendance au POINT D'ENTRÉE est tout le défaut — sans cette distinction elle mesurerait « ce couple est cassé », ce qui est faux, et non « ce couple ne s'ouvre que par un côté ». Sortie de l'enfant :\n${surAutrePorte.brut}`);
      process.exit(2);
    }
    console.log(`[porte] la sonde est validée DANS LES DEUX SENS sur des modules FABRIQUÉS, hors du dépôt : un module sain est vu se charger ; un couple en cycle dont un corps appelle son partenaire en colonne 1 est vu JETER par sa porte fautive (\`${surFautive.type}\` — ${surFautive.message}), et c'est bien une erreur d'ÉVALUATION, pas d'édition de liens ; et le MÊME couple, ouvert par son AUTRE porte, se charge — la sonde mesure donc la dépendance au point d'entrée, pas une cassure.`);
  } finally {
    rmSync(bac, { recursive: true, force: true });
  }

  // ------ LA MESURE : UN PROCESSUS NEUF PAR PORTE ------
  if (modules.length < PLANCHER_MODULES) {
    console.error(`::error::(1a-instrument) seulement ${modules.length} modules découverts sous web/, plancher ${PLANCHER_MODULES} : la découverte est cassée, et un plafond mesuré sur ce corpus amputé ne voudrait rien dire.`);
    process.exit(2);
  }
  const portesQuiJettent = [];
  for (const f of modules) {
    const r = ouvrirLeGraphePar(path.join(WEB, f));
    if (r.code === 0) continue;
    if (r.code !== 3) {
      console.error(`::error::(1a-instrument) l'ouverture du graphe par \`web/${f}\` s'est terminée sur le code ${r.code} — ni « se charge » (0) ni « jette » (3) : l'enfant est mort d'autre chose, et ce banc refuse de conclure plutôt que de compter cette porte saine. Sortie de l'enfant :\n${r.brut}`);
      process.exit(2);
    }
    // Le site est rendu RELATIF à la racine du dépôt : c'est la ligne à ouvrir, pas un chemin de machine.
    portesQuiJettent.push({ f, type: r.type, message: r.message, site: String(r.site || "").replace(pathToFileURL(RACINE).href + "/", "") });
  }

  // LE PLAFOND EST DATÉ, ET LA COMPARAISON EST « AU PLUS » — jamais une égalité, jamais un plancher.
  // L'INCLUSION EST LE « AU PLUS » DES ENSEMBLES : une porte qui GUÉRIT laisse ce témoin VERT, une
  // porte NOUVELLE le fait rougir en la NOMMANT. Le jour où le graphe devient agnostique au point
  // d'entrée, la liste mesurée est vide et le témoin est vert sans qu'une ligne bouge. Un témoin qui
  // ne peut être vert que tant que le chantier est ouvert n'est pas une garde, c'est une RANÇON — ce
  // dépôt en a déjà payé une (voir le témoin 53), et cette borne-ci n'en est pas une.
  const PORTES_QUI_JETTENT_AU_2026_08_30 = ["attack.js", "navigation.js", "threatintel.js"];
  const nouvelles = portesQuiJettent.map((p) => p.f).filter((f) => !PORTES_QUI_JETTENT_AU_2026_08_30.includes(f));
  exiger(nouvelles.length === 0,
    `(1a) ${nouvelles.length} porte(s) d'entrée JETTENT qui ne le faisaient pas au relevé du 2026-08-30 (${nouvelles.join(", ")}) : ouvrir le graphe de modules par ce fichier, dans un processus neuf, s'arrête sur une erreur d'ÉVALUATION. Détail : ${portesQuiJettent.filter((p) => nouvelles.includes(p.f)).map((p) => `web/${p.f} -> ${p.type} : ${p.message} (site de premier niveau : ${p.site})`).join(" ; ")}. Le relevé de référence est ["${PORTES_QUI_JETTENT_AU_2026_08_30.join('", "')}"] — une porte de MOINS est un reste fermé et laisse ce témoin vert ; cette borne se REMESURE et se réécrit, elle n'exige jamais que le défaut survive.`);

  const guerie = PORTES_QUI_JETTENT_AU_2026_08_30.filter((f) => !portesQuiJettent.some((p) => p.f === f));
  console.log(`[porte] ${modules.length} portes d'entrée ouvertes CHACUNE dans un processus NEUF (le seul protocole qui mesure quoi que ce soit ici : dans un processus unique, l'ordre alphabétique perd 0 module et une autre porte en perd 23). ${portesQuiJettent.length} JETTENT, au plus les ${PORTES_QUI_JETTENT_AU_2026_08_30.length} du relevé daté du 2026-08-30${guerie.length ? ` (${guerie.length} guérie(s) depuis : ${guerie.join(", ")} — cette borne peut descendre)` : ""} :${portesQuiJettent.length ? "\n  · " + portesQuiJettent.map((p) => `web/${p.f} -> ${p.type} : ${p.message} — site de premier niveau ${p.site}`).join("\n  · ") : " aucune"}\n  CE QUE CE TÉMOIN NE TIENT PAS : le défaut est LATENT — \`index.html\` n'ouvre le graphe que par \`app.js\`, donc rien n'est cassé à l'écran et ce témoin ne mesure pas un incident, il mesure la portabilité du graphe ; il ne dit RIEN des modules qui se chargent mais dont l'ÉTAT diffère selon la porte ; et la comparaison porte sur les NOMS — une porte qui guérit pendant qu'une autre casse, à compte égal, est vue (la nouvelle est nommée), mais un module RENOMMÉ rougira comme une régression tant que ce relevé n'est pas réécrit.`);
}

const liens = [];
for (const f of modules) {
  try {
    await import(pathToFileURL(path.join(WEB, f)).href);
  } catch (e) {
    // `PLUME_HARNAIS_PILE=1` ajoute la PILE d'appel au message. Sans elle, « module qui ne se charge pas »
    // nomme le module IMPORTÉ, pas le site fautif — or une seule ligne fautive fait tomber 23 modules par
    // cascade, et c'est le site qu'il faut corriger. Mesuré à l'usage : c'est ce qui a montré que la liste
    // des quatre lectures nues de `localStorage` (celle de la critique adverse) en oubliait TROIS autres.
    liens.push(`${f} : ${e && e.name} — ${e && e.message}${process.env.PLUME_HARNAIS_PILE === "1" ? "\n" + (e && e.stack) : ""}`);
  }
}
if (liens.length) {
  for (const l of liens) console.error(`::error::module web qui ne se charge pas : ${l}`);
  console.error(`\n${liens.length} module(s) sur ${modules.length} ne se chargent pas : l'interface serait VIDE.`);
  process.exit(1);
}
// ---------------------------------------------------------------------------------------------
// 1bis. LE GRAPHE SE LIE ENCORE QUAND LE NAVIGATEUR REFUSE LE STOCKAGE DE SITE (`P4.13-a`, reprise).
//    Dans le mode, le banc a déjà tout mesuré à la section 1 ci-dessus : il rend son verdict et s'arrête
//    là (les sections suivantes exercent des surfaces qui LISENT le stockage à dessein, sous `try`, et
//    n'ont rien à dire sur ce mode). Hors du mode, il se relance dans le mode et EXIGE que ce sous-banc
//    conclue : c'est la seule façon d'obtenir une seconde ÉVALUATION des modules sans rejouer leurs
//    effets de bord ici. La mutation est directe — retirer le `try` de `lireLeStockageDuSite`
//    (`web/state.js`) fait rougir ce témoin, et lui seul.
// ---------------------------------------------------------------------------------------------
if (STOCKAGE_REFUSE) {
  // -------------------------------------------------------------------------------------------
  // 1quater. UN CHOIX D'INTERFACE VA JUSQU'AU BOUT QUAND L'ÉCRITURE EST REFUSÉE (`P4.13-b`). La
  //    section 1bis prouve que le graphe se LIE sans stockage ; elle ne dit RIEN de ce qui se passe
  //    quand l'exploitant CLIQUE. Or les écritures, elles, sont restées nues après `P4.13-a` : au
  //    basculement de thème, `data-theme` était posé, PUIS `localStorage.setItem` jetait DANS le
  //    gestionnaire de clic — `paint()`, `refresh()` et `loadDashboard()` n'étaient jamais atteints.
  //    Le fond basculait, l'icône restait celle de l'ANCIEN thème, les graphes gardaient leur couleur :
  //    un état INCOHÉRENT, pire qu'une perte, parce qu'il n'y a rien à lire pour le comprendre.
  //    TROIS exigences, et un CONTRÔLE POSITIF sans lequel elles seraient vraies par vacuité.
  // -------------------------------------------------------------------------------------------
  const btnTheme = document.querySelector("#theme");
  if (!btnTheme) {
    console.error("::error::(1quater) `#theme` est absent d'index.html : le basculement de thème ne peut pas être exercé, et l'exigence ci-dessous ne mesurerait rien.");
    process.exit(2);
  }
  const iconeAvant = btnTheme.innerHTML;
  const avisAvant = document.querySelectorAll(".toast").length;
  let leveTheme = null;
  try { btnTheme.click(); } catch (e) { leveTheme = `${e && e.name} — ${e && e.message}`; }
  const themeApres = document.documentElement.dataset.theme;
  const montreLaLune = /M21 13A9 9/.test(btnTheme.innerHTML);
  const avis = document.querySelectorAll(".toast").map((t) => t.textContent).slice(avisAvant);
  if (leveTheme) {
    console.error(`::error::(1quater) le basculement de thème JETTE quand le navigateur refuse le stockage de site (${leveTheme}) : une ÉCRITURE NUE de \`localStorage\` s'exécute dans le gestionnaire de clic, APRÈS la pose de \`data-theme\` et AVANT la repeinte de l'icône — l'exploitant voit une interface à MOITIÉ basculée, sans un mot. L'écriture doit passer par \`ecrireDansLeStockageDuSite\` (web/state.js), qui REND le refus au lieu de le jeter.`);
    process.exit(1);
  }
  if ((themeApres === "light") !== montreLaLune) {
    console.error(`::error::(1quater) après le basculement, \`data-theme\` vaut \`${themeApres}\` mais l'icône montre « ${montreLaLune ? "lune" : "soleil"} » : la chaîne du clic n'est pas allée jusqu'à \`paint()\`. L'interface est à moitié basculée.`);
    process.exit(1);
  }
  if (!avis.length) {
    console.error("::error::(1quater) le thème a bien basculé, mais RIEN n'a été dit à l'exploitant alors que la persistance a été refusée : un refus avalé en silence échange l'état incohérent contre une perte MUETTE — l'exploitant croit son choix retenu et retrouvera l'ancien thème sans jamais savoir pourquoi.");
    process.exit(1);
  }
  if (iconeAvant === btnTheme.innerHTML) {
    console.error("::error::(1quater) CONTRÔLE POSITIF PERDU : l'icône du thème n'a pas changé DU TOUT — le clic n'a rappelé aucun gestionnaire, et les trois exigences ci-dessus seraient vraies par vacuité.");
    process.exit(2);
  }
  console.log(`[stockage] le basculement de thème va JUSQU'AU BOUT sans stockage de site : \`data-theme\` = ${themeApres}, icône repeinte en accord, et l'exploitant est AVERTI que le choix ne sera pas retenu (« ${avis[0]} »).`);

  // -------------------------------------------------------------------------------------------
  // 1quinquies. LES TROIS AUTRES CHOIX D'INTERFACE VONT AUSSI JUSQU'AU BOUT (`P4.13-b`). Le témoin
  //    1quater ci-dessus n'exerce QU'UN site — le thème. Il ne dit rien des trois autres écritures qui
  //    s'exécutaient nues DANS un gestionnaire, et qui rendaient exactement le même défaut : un état
  //    posé, une vue jamais repeinte, et rien à lire. Mesuré le 2026-08-30, avant correctif : le tri des
  //    règles passait `S.ruleSort` de `id` à `sev` sans que `#rule-list` soit repeinte, le tri des
  //    parsers faisait de même sur `#parser-list`, et un glisser-déposer de carte DLP laissait les cinq
  //    cartes dans l'ordre `whoami, tamper, fim, acl, rbac` — inchangé — en levant `SecurityError`.
  //    QUATRE exigences par site, dont un CONTRÔLE POSITIF sans lequel les trois autres seraient vraies
  //    par vacuité : si le geste n'a RIEN produit, ce n'est pas une preuve que rien n'a cassé.
  // -------------------------------------------------------------------------------------------
  {
    const modEtat = await import(pathToFileURL(path.join(WEB, "state.js")).href);
    const modAccesDonnees = await import(pathToFileURL(path.join(WEB, "dataaccess.js")).href);
    const etat = modEtat.S;
    const battement = () => new Promise((r) => setTimeout(r, 0));
    const avis = () => document.querySelectorAll(".toast").map((t) => t.textContent);
    const marquer = (hote) => { const m = document.createElement("div"); m.className = "temoin-non-repeint"; hote.replaceChildren(m); };

    // (a) et (b) : les deux tris persistés. MÊME forme, seuls la cible, l'état et la valeur changent.
    for (const t of [
      { nom: "tri des règles", selecteur: "#rule-sort", liste: "#rule-list", valeur: "sev", etat: "ruleSort", site: "web/detection_admin.js" },
      { nom: "tri des parsers", selecteur: "#parser-sort", liste: "#parser-list", valeur: "source", etat: "parserSort", site: "web/detection_admin.js" },
    ]) {
      const sel = document.querySelector(t.selecteur), liste = document.querySelector(t.liste);
      if (!sel || typeof sel.onchange !== "function") {
        console.error(`::error::(1quinquies) \`${t.selecteur}\` n'a pas de gestionnaire \`onchange\` : le ${t.nom} ne peut pas être exercé, et l'exigence ci-dessous ne mesurerait rien.`);
        process.exit(2);
      }
      marquer(liste);
      const avantAvis = avis().length, avantEtat = etat[t.etat];
      sel.value = t.valeur;
      let leve = null;
      try { sel.onchange(); } catch (e) { leve = `${e && e.name} — ${e && e.message}`; }
      await battement(); await battement(); await battement();
      const repeinte = liste.querySelectorAll(".temoin-non-repeint").length === 0;
      const dits = avis().slice(avantAvis);
      if (leve) {
        console.error(`::error::(1quinquies) le ${t.nom} JETTE quand le navigateur refuse le stockage de site (${leve}) : une ÉCRITURE NUE de \`localStorage\` s'exécute dans le gestionnaire, APRÈS la pose de \`S.${t.etat}\` et AVANT la repeinte de la liste — le sélecteur annonce un tri que la liste n'applique pas. L'écriture doit passer par \`ecrireDansLeStockageDuSite\` (web/state.js), qui REND le refus au lieu de le jeter (${t.site}).`);
        process.exit(1);
      }
      if (etat[t.etat] === avantEtat) {
        console.error(`::error::(1quinquies) CONTRÔLE POSITIF PERDU : \`S.${t.etat}\` vaut toujours « ${avantEtat} » après le changement de \`${t.selecteur}\` — le gestionnaire n'a rien fait, et les exigences ci-dessous seraient vraies par vacuité.`);
        process.exit(2);
      }
      if (!repeinte) {
        console.error(`::error::(1quinquies) \`S.${t.etat}\` est passé à « ${etat[t.etat]} » mais \`${t.liste}\` n'a pas été repeinte : la chaîne du changement ne va pas jusqu'au rendu. Le ${t.nom} est à moitié appliqué — le sélecteur dit une chose, la liste en montre une autre.`);
        process.exit(1);
      }
      if (!dits.length) {
        console.error(`::error::(1quinquies) le ${t.nom} a été appliqué, mais RIEN n'a été dit à l'exploitant alors que la persistance a été refusée : un refus avalé en silence échange l'état incohérent contre une perte MUETTE — l'exploitant croit son tri retenu et retrouvera l'ancien au prochain chargement.`);
        process.exit(1);
      }
      console.log(`[stockage] le ${t.nom} va JUSQU'AU BOUT sans stockage de site : \`S.${t.etat}\` = ${etat[t.etat]}, \`${t.liste}\` repeinte en accord, et l'exploitant est AVERTI (« ${dits[0]} »).`);
    }

    // (c) le glisser-déposer des cartes DLP. Sa persistance n'a AUCUN jumeau serveur : sans repli en
    //     mémoire, un navigateur qui refuse le stockage rendait le geste INERTE — c'est ce que
    //     l'ordre AVANT/APRÈS mesure, et pas seulement l'absence d'exception.
    {
      const hote = document.querySelector("#da-body");
      hote.replaceChildren();
      modAccesDonnees.renderDataAccess();
      await battement(); await battement(); await battement();
      const ordre = () => hote.querySelectorAll(".card[data-da]").map((c) => c.dataset.da);
      const avantOrdre = ordre(), cartes = hote.querySelectorAll(".card[data-da]");
      if (cartes.length < 2) {
        console.error(`::error::(1quinquies) \`#da-body\` porte ${cartes.length} carte(s) après \`renderDataAccess()\` : le glisser-déposer ne peut pas être exercé, et l'exigence ci-dessous ne mesurerait rien.`);
        process.exit(2);
      }
      const avantAvis = avis().length;
      const glissee = avantOrdre[avantOrdre.length - 1];
      const depot = new Evenement("drop", { bubbles: false });
      depot.dataTransfer = { types: ["text/soc-da"], getData: () => glissee };
      let leve = null;
      try { cartes[0].dispatchEvent(depot); } catch (e) { leve = `${e && e.name} — ${e && e.message}`; }
      const apresOrdre = ordre(), dits = avis().slice(avantAvis);
      if (leve) {
        console.error(`::error::(1quinquies) le glisser-déposer des cartes d'accès aux données JETTE quand le navigateur refuse le stockage de site (${leve}) : l'écriture NUE de \`localStorage\` s'exécute entre le calcul du nouvel ordre et sa pose, donc \`applyDaOrder()\` n'est jamais atteint et la carte revient à sa place sans un mot (web/dataaccess.js).`);
        process.exit(1);
      }
      if (JSON.stringify(apresOrdre) === JSON.stringify(avantOrdre)) {
        console.error(`::error::(1quinquies) après le dépôt, l'ordre des cartes est INCHANGÉ (${apresOrdre.join(", ")}) : le geste n'a rien appliqué. La persistance de cet ordre n'a aucun jumeau serveur — sans repli en mémoire, un navigateur qui refuse le stockage rend le réordonnancement inerte.`);
        process.exit(1);
      }
      if (!dits.length) {
        console.error("::error::(1quinquies) les cartes ont bien été réordonnées, mais RIEN n'a été dit à l'exploitant alors que la persistance a été refusée : il croira son agencement retenu et le retrouvera défait au prochain chargement.");
        process.exit(1);
      }
      console.log(`[stockage] le réordonnancement des cartes d'accès aux données va JUSQU'AU BOUT sans stockage de site : ${avantOrdre.join(", ")} -> ${apresOrdre.join(", ")}, et l'exploitant est AVERTI (« ${dits[0]} »).`);
    }
  }

  console.log(`OK — ${modules.length} modules web se lient alors que l'accès au stockage de site JETTE (SecurityError) : l'écran de connexion reste atteignable chez un navigateur qui bloque le stockage.`);
  process.exit(0);
}
{
  const { spawnSync } = await import("node:child_process");
  const r = spawnSync(process.execPath, [new URL(import.meta.url).pathname], {
    env: { ...process.env, PLUME_HARNAIS_STOCKAGE_REFUSE: "1" },
    encoding: "utf8",
  });
  const sortie = `${r.stdout || ""}${r.stderr || ""}`;
  if (r.status !== 0) {
    console.error(`::error::le graphe de modules NE SE LIE PAS quand le navigateur refuse le stockage de site : une lecture NUE de \`localStorage\` s'exécute à l'évaluation d'un module, donc avant tout \`catch\` applicatif — le visiteur reçoit un écran muet, sans formulaire de connexion et sans message. Sortie du sous-banc :
${sortie}`);
    process.exit(1);
  }
  if (!/le basculement de thème va JUSQU'AU BOUT sans stockage de site/.test(sortie)) {
    console.error(`::error::CONTRÔLE POSITIF PERDU : le sous-banc « stockage refusé » n'a pas prononcé le verdict du BASCULEMENT DE THÈME (1quater) — il n'a donc pas exercé le clic. Sortie :
${sortie}`);
    process.exit(2);
  }
  if (!/modules web se lient alors que l'accès au stockage de site JETTE/.test(sortie)) {
    console.error(`::error::CONTRÔLE POSITIF PERDU : le sous-banc « stockage refusé » a rendu 0 sans prononcer son verdict — il n'a donc rien mesuré. Sortie :
${sortie}`);
    process.exit(2);
  }
  console.log(`[stockage] ${modules.length} modules web se lient AUSSI quand l'accès à localStorage jette (SecurityError) — sous-banc relancé, verdict prononcé.`);
}

// ---------------------------------------------------------------------------------------------
// 1ter. LE SEUL ACCÈS DOM NON GARDÉ DU TOP-LEVEL D'`app.js` EST TENU PAR UN CONTRÔLE POSITIF, PAS PAR
//    UN ACCIDENT (`P4.13-a`, reprise). `app.js:288` déréférence `$('#q')` sans garde, 521 lignes AVANT
//    `initAuthGate()` — ses ~40 voisins, eux, sont de la forme `if ($('#x')) …`. La critique adverse
//    proposait de le garder comme eux. MESURÉ, et c'est ce qui a fait refuser le remède : en retirant
//    `id="q"` d'`index.html`, ce banc rougit en nommant **23 modules sur 49** qui ne se chargent plus.
//    Garder la ligne rendrait ce défaut SILENCIEUX — un champ de recherche mort, aucun rouge. Le rouge
//    existant était pourtant ACCIDENTEL (un `TypeError` qu'aucun témoin ne réclamait) : il est remplacé
//    ici par une exigence EXPLICITE — l'élément existe, et le raccourci de la barre d'en-tête est câblé.
//    Ce qui borne le prix du refus : le filet des 6 s d'`index.html`, désormais autorisé par la CSP du
//    démon, révèle l'aveu d'échec d'amorçage — l'écran n'est plus MUET quand `app.js` s'interrompt.
// ---------------------------------------------------------------------------------------------
{
  const q = document.getElementById("q");
  if (!q) {
    console.error("::error::(1ter) `#q` (la barre de recherche de l'en-tête) est absent d'index.html : `app.js:288` déréférence `$('#q')` SANS garde au top-level, donc l'évaluation d'app.js s'interrompt, `initAuthGate()` n'est jamais atteint et l'écran de connexion ne se peint pas.");
    process.exit(1);
  }
  // DEUX capteurs `keydown`, et on les NOMME : `app.js:288` (Entrée -> recopie dans l'éditeur de requête,
  // ouvre l'onglet, exécute — P11.7-a) et `app.js:793` (Échap -> referme la liste de suggestions). Un
  // compte EXACT plutôt qu'un plancher : retirer l'un des deux est une décision, elle doit se voir.
  const clavier = (q._ecouteurs || []).filter((e) => e.type === "keydown");
  if (clavier.length !== 2) {
    console.error(`::error::(1ter) la barre de recherche de l'en-tête porte ${clavier.length} capteur(s) \`keydown\` au lieu des deux attendus (app.js:288 « Entrée -> éditeur de requête » et app.js:793 « Échap -> ferme les suggestions ») : un câblage a disparu, ou un troisième est arrivé sans décision.`);
    process.exit(1);
  }
  console.log("[amorçage] la barre de recherche de l'en-tête existe et porte ses DEUX capteurs `keydown` (Entrée -> éditeur de requête, Échap -> ferme les suggestions) — le seul déréférencement DOM non gardé du top-level d'app.js est tenu par une exigence, plus par un TypeError accidentel.");
}

// Relevé ICI, avant toute instance sous `LANG='en'` : ce que la liaison française a posé sur le corps du document.
const observateursSurLeCorpsApresLiaison = observateursPoses.filter((o) => o.cible === document.body).length;
if (modules.length < PLANCHER_MODULES) {
  console.error(`::error::seulement ${modules.length} modules découverts sous web/, plancher ${PLANCHER_MODULES} : la découverte est cassée, le harnais refuse de conclure.`);
  process.exit(2);
}

// ---------------------------------------------------------------------------------------------
// 37. LES CINQ CÉCITÉS FERMÉES ONT CHACUNE LEUR TÉMOIN (`P11.13-g`). Elles rendaient toutes VERT sur un
//     défaut RÉEL, et rien n'empêchait de les rouvrir : un `addEventListener` remis à `{}`, un `dataset`
//     redevenu objet nu, un `innerHTML` qui ne fait que retenir sa chaîne. Chacune est donc EXERCÉE ici,
//     avec le témoin NÉGATIF du comportement d'avant reconstitué à la main — sans lui, un vérificateur
//     muet passerait pour une preuve — et, là où un zéro doit être interprété, avec le CONTRÔLE POSITIF
//     qui distingue « absent » de « invisible à cet instrument ».
//     La sixième, la mise en page, ne se ferme pas : elle se DÉCLARE (section 0).
// ---------------------------------------------------------------------------------------------
{
  // ---- (a) LE CHEMIN D'UN ÉVÉNEMENT ----
  const racine = document.createElement("div"), ligne = document.createElement("tr"), bouton = document.createElement("button");
  racine.appendChild(ligne); ligne.appendChild(bouton);
  bouton.setAttribute("data-act", "ack");
  const trace = [];
  racine.addEventListener("click", (e) => trace.push(`capture:${e.currentTarget.tagName}:${e.target.tagName}`), true);
  ligne.addEventListener("click", (e) => trace.push(`remontée:${e.currentTarget.tagName}:${e.target.tagName}`));
  bouton.addEventListener("click", (e) => trace.push(`cible:${e.currentTarget.tagName}:${e.target.tagName}`));
  bouton.click();
  exiger(trace.join(" | ") === "capture:DIV:BUTTON | cible:BUTTON:BUTTON | remontée:TR:BUTTON",
    `(37a) le chemin d'un clic n'est pas capture -> cible -> remontée, ou « target » désigne le nœud qui ÉCOUTE : ${trace.join(" | ") || "(aucun écouteur rappelé)"}`);

  // TÉMOIN NÉGATIF : le shim d'AVANT, reconstitué à la main. Le même vérificateur doit le voir MUET.
  const inerte = { _t: [], addEventListener() {}, dispatchEvent() { return true; }, click() {} };
  inerte.addEventListener("click", () => inerte._t.push("vu"));
  inerte.click(); inerte.dispatchEvent({ type: "click" });
  exiger(inerte._t.length === 0 && trace.length === 3,
    `(37a-négatif) le vérificateur ne distingue pas un répartiteur inerte (${inerte._t.length} rappel) d'un vrai (${trace.length}) : le témoin (37a) ne prouverait rien`);

  // LA DÉLÉGATION, qui est le câblage majoritaire de la console : l'écouteur vit sur l'ancêtre et
  // retrouve la ligne par `e.target.closest(…)`. Elle avait DEUX raisons de ne pas marcher ici.
  let pris = null;
  racine.addEventListener("click", (e) => { const c = e.target.closest("[data-act]"); pris = c && c.getAttribute("data-act"); });
  bouton.click();
  exiger(pris === "ack", `(37a) délégation : « ${pris} » au lieu de « ack » — un écouteur d'ancêtre ne retrouve pas sa cible par closest`);

  // `preventDefault` et `stopPropagation` ont un EFFET, et la valeur qui change le dit.
  const avant = trace.length;
  ligne.addEventListener("click", (e) => e.stopPropagation());
  const passe = bouton.dispatchEvent(new Evenement("click", { bubbles: true }));
  const apres = trace.length;
  exiger(passe === true, "(37a) un clic que personne n'annule est rendu comme annulé");
  const empeche = document.createElement("a");
  empeche.addEventListener("click", (e) => e.preventDefault());
  exiger(empeche.dispatchEvent(new Evenement("click", {})) === false, "(37a) `preventDefault` n'a aucun effet observable : un geste annulé passe pour accepté");
  exiger(apres - avant === 3, `(37a) stopPropagation : ${apres - avant} étape(s) vues au lieu de 3 (capture, cible, la remontée s'arrête sur la ligne) — la propagation ne s'arrête pas`);

  // UN NŒUD DÉTACHÉ NE RÉVEILLE PAS LES CAPTEURS DU DOCUMENT : c'est ce qui distingue « posé » de
  // « joignable », et c'est la question que la fermeture des modales avait déjà posée (`P11.13-e`).
  let vusParLeDocument = 0;
  const capteur = () => { vusParLeDocument++; };
  document.addEventListener("clic-temoin", capteur, true);
  bouton.dispatchEvent(new Evenement("clic-temoin", { bubbles: true }));
  const horsDocument = vusParLeDocument;
  const dansLaPage = document.createElement("span");
  document.body.appendChild(dansLaPage);
  dansLaPage.dispatchEvent(new Evenement("clic-temoin", { bubbles: true }));
  const attache = vusParLeDocument;
  dansLaPage.remove();
  document.removeEventListener("clic-temoin", capteur, true);
  exiger(horsDocument === 0 && attache === 1, `(37a) chemin jusqu'au document : détaché ${horsDocument} (0 attendu), rattaché ${attache - horsDocument} (1 attendu) — un capteur global voit, ou ne voit pas, ce qu'il ne devrait pas`);

  // CONTRÔLE POSITIF SUR LE DOCUMENT RÉEL : le registre n'est pas vrai que sur des jouets. La console
  // a réellement câblé des écouteurs sur des nœuds de la page pendant le chargement des modules.
  const porteurs = (n, acc) => { if (n._ecouteurs && n._ecouteurs.length) acc.push(n); (n.children || []).forEach((c) => porteurs(c, acc)); return acc; };
  const cables = porteurs(document.body, []);
  exiger(cables.length > 0 && ecouteursDuDocument.length > 0,
    `(37a) contrôle positif : ${cables.length} nœud(s) de la page portent un écouteur et ${ecouteursDuDocument.length} sur le document — un zéro ici voudrait dire que le registre n'enregistre rien, pas que la console ne câble rien`);

  // ---- (b) `disabled` EST UN ATTRIBUT ----
  const inactif = document.createElement("button"), actif = document.createElement("button");
  const cadre = document.createElement("div"); cadre.appendChild(inactif); cadre.appendChild(actif);
  inactif.disabled = true;
  exiger(inactif.hasAttribute("disabled") && inactif.getAttribute("disabled") === "" && inactif.disabled === true,
    `(37b) « disabled » posé par propriété ne pose pas l'attribut booléen : hasAttribute=${inactif.hasAttribute("disabled")}, getAttribute=${JSON.stringify(inactif.getAttribute("disabled"))}`);
  exiger(cadre.querySelectorAll("[disabled]").length === 1 && cadre.querySelector("[disabled]") === inactif,
    `(37b) le sélecteur [disabled] trouve ${cadre.querySelectorAll("[disabled]").length} bouton(s) au lieu du seul qui l'est`);
  inactif.disabled = false;
  exiger(!inactif.hasAttribute("disabled") && cadre.querySelectorAll("[disabled]").length === 0,
    "(37b) « disabled » remis à faux laisse l'attribut posé : un contrôle rendu à l'exploitant continuerait de se lire inerte");
  inactif.setAttribute("disabled", "");
  exiger(inactif.disabled === true, "(37b) l'attribut posé par le balisage ne se relit pas en propriété : le reflet ne va que dans un sens");
  const sansReflet = { disabled: true, hasAttribute: () => false };
  exiger(sansReflet.hasAttribute("disabled") === false, "(37b-négatif) le vérificateur ne voit pas un `disabled` sans reflet : le témoin (37b) ne prouverait rien");

  // ---- (c) LE BALISAGE POSÉ EN BLOC EST UN SOUS-ARBRE ----
  const porteur = document.createElement("div");
  porteur.innerHTML = '<div class="boite"><b>2</b> muet(s) &amp; 1 &laquo;&nbsp;calme&nbsp;&raquo;<button class="btn" data-act="ack-all" disabled>Tout acquitter</button></div>';
  const boite = porteur.querySelector(".boite"), acquitter = porteur.querySelector('[data-act="ack-all"]');
  exiger(!!boite && boite.tagName === "DIV" && boite.classList.contains("boite"), `(37c) le sous-arbre posé en bloc n'est pas analysé : « ${boite && boite.tagName} » rendu pour .boite`);
  exiger(!!acquitter && acquitter.dataset.act === "ack-all" && acquitter.disabled === true && acquitter.textContent === "Tout acquitter",
    `(37c) l'attribut de données, l'état inerte ou le texte du bouton posé en bloc ne survivent pas : ${acquitter ? JSON.stringify([acquitter.dataset.act, acquitter.disabled, acquitter.textContent]) : "(bouton introuvable)"}`);
  // Les lectures qui suivent sont NULL-SÛRES : quand la cécité revient, ce témoin doit NOMMER ce qu'il
  // voit, pas s'arrêter sur une exception qui n'apprend rien — un banc qui casse ne dit pas pourquoi.
  // `&nbsp;` DOIT rendre une espace insécable, pas une espace ordinaire : c'est la différence que la
  // console emploie pour ne pas couper « 3 h » en fin de ligne, et une comparaison laxiste la manquerait.
  exiger(porteur.textContent.includes("2 muet(s) & 1 \u00ab\u00a0calme\u00a0\u00bb"), `(37c) le texte d'un bloc posé ainsi n'est pas lisible (entités non décodées ?) : « ${porteur.textContent} » (codes : ${[...porteur.textContent].slice(0, 30).map((c) => c.codePointAt(0)).join(",")})`);
  exiger(!!boite && boite.children.length === 2 && boite.childNodes.length > boite.children.length,
    `(37c) « children » et « childNodes » sont la même liste : ${boite ? boite.children.length + " enfant(s) élément, " + boite.childNodes.length + " nœud(s)" : "(boîte introuvable)"} — un nœud texte passerait pour un élément`);
  // TÉMOIN NÉGATIF : le porteur d'AVANT, qui ne fait que retenir la chaîne.
  const avantParse = { _h: "", set innerHTML(v) { this._h = v; }, get textContent() { return ""; }, querySelector() { return document.createElement("div"); } };
  avantParse.innerHTML = '<div class="boite">x</div>';
  exiger(avantParse.querySelector(".boite").tagName === "DIV" && avantParse.textContent === "" && !!boite && boite.textContent !== "",
    `(37c-négatif) le vérificateur ne distingue pas un balisage ANALYSÉ d'un balisage seulement RETENU : le nœud de repli a le même air qu'un vrai (analysé : ${boite ? JSON.stringify(boite.textContent) : "(rien)"})`);
  // CONTRÔLE POSITIF SUR LE DOCUMENT RÉEL : la page entière est posée par CE MÊME lecteur, en bloc.
  // Sans ce contrôle, un zéro plus haut ne dirait pas si le mécanisme est cassé ou s'il ne sert jamais —
  // et c'est la distinction qui a manqué cinq fois. La page est ici la seule source : rien n'est énuméré.
  const tousLesNoeuds = (n, acc) => { for (const c of n.children || []) { acc.push(c); tousLesNoeuds(c, acc); } return acc; };
  const noeudsDeLaPage = tousLesNoeuds(document.body, []);
  const porteursDeDonnees = noeudsDeLaPage.filter((n) => Object.keys(n.attributes).some((k) => k.startsWith("data-")));
  const premierPorteur = porteursDeDonnees[0];
  exiger(noeudsDeLaPage.length > 500 && porteursDeDonnees.length > 0,
    `(37c) contrôle positif : ${noeudsDeLaPage.length} élément(s) analysés depuis index.html, dont ${porteursDeDonnees.length} porteurs d'un attribut de données — à zéro, les témoins ci-dessus ne diraient rien du document réel`);
  exiger(!!premierPorteur && Object.keys(premierPorteur.dataset).length > 0,
    `(37c) contrôle positif : « ${premierPorteur && premierPorteur.tagName} » porte ${premierPorteur ? Object.keys(premierPorteur.attributes).filter((k) => k.startsWith("data-")).join(", ") : "(rien)"} dans le document, et son dataset en rend ${premierPorteur ? Object.keys(premierPorteur.dataset).length : 0} : le reflet ne franchit pas la page réelle`);
  const parBloc = porteursDeDonnees.length;

  // ---- (d) UN IDENTIFIANT ABSENT REND `null` ----
  const ABSENT = "identifiant-que-la-page-ne-porte-pas-temoin";
  exiger(document.getElementById(ABSENT) === null && document.querySelector("#" + ABSENT) === null,
    `(37d) un identifiant absent rend ${JSON.stringify(String(document.getElementById(ABSENT)))} au lieu de null`);
  // CONTRÔLE POSITIF, tiré de la page et non écrit ici : sans lui, un document qui ne rendrait JAMAIS
  // rien passerait ce témoin, et « absent » ne se distinguerait pas de « invisible à cet instrument ».
  const present = document.getElementById(UN_ID_DE_LA_PAGE);
  exiger(!!present && present.id === UN_ID_DE_LA_PAGE, `(37d) contrôle positif : l'identifiant « ${UN_ID_DE_LA_PAGE} », qui EST dans la page, rend ${present ? "un nœud d'id « " + present.id + " »" : "null"}`);
  // LA GARDE DE POSE, c'est-à-dire ce que la cécité cassait : « si c'est déjà là, ne rien faire ».
  let poses = 0;
  const poser = () => { if (document.getElementById("temoin-de-pose")) return; const n = document.createElement("div"); n.id = "temoin-de-pose"; document.body.appendChild(n); poses++; };
  poser(); poser(); poser();
  const pose = document.getElementById("temoin-de-pose");
  if (pose) pose.remove();
  exiger(poses === 1, `(37d) garde de pose : ${poses} pose(s) au lieu d'une seule — à zéro, la garde répond « déjà posé » sur un nœud que personne n'a posé, ce qui est la cécité mesurée`);

  // ---- (e) `dataset` ET `data-*` SONT LA MÊME DONNÉE ----
  const palier = document.createElement("li");
  palier.dataset.seuil = 80;
  exiger(palier.getAttribute("data-seuil") === "80" && palier.dataset.seuil === "80",
    `(37e) une valeur posée par dataset ne devient pas un attribut, ou revient autrement : attribut ${JSON.stringify(palier.getAttribute("data-seuil"))}, dataset ${JSON.stringify(palier.dataset.seuil)}`);
  exiger(typeof palier.dataset.seuil === "string", `(37e) dataset rend un ${typeof palier.dataset.seuil} : un dataset réel ne rend QUE des chaînes, et une comparaison numérique y serait fausse`);
  palier.setAttribute("data-ac-lie", "1");
  exiger(palier.dataset.acLie === "1", `(37e) l'attribut « data-ac-lie » ne se relit pas en « acLie » : ${JSON.stringify(palier.dataset.acLie)}`);
  exiger(Object.keys(palier.dataset).sort().join(",") === "acLie,seuil", `(37e) l'énumération de dataset rend « ${Object.keys(palier.dataset).sort().join(",")} »`);
  delete palier.dataset.seuil;
  exiger(!palier.hasAttribute("data-seuil") && palier.dataset.seuil === undefined, "(37e) retirer une clé de dataset ne retire pas l'attribut");
  exiger(palier.dataset.jamaisPosee === undefined, "(37e) une clé jamais posée ne rend pas undefined : toute garde « cette valeur est-elle posée ? » répondrait oui");
  const datasetNu = { dataset: {}, getAttribute: () => null };
  datasetNu.dataset.seuil = 80;
  exiger(datasetNu.getAttribute("data-seuil") === null && palier.getAttribute("data-ac-lie") === "1",
    "(37e-négatif) le vérificateur ne distingue pas un dataset qui REFLÈTE d'un objet nu : le témoin (37e) ne prouverait rien");

  console.log(`[cécités] cinq des six cécités mesurées le 2026-08-25 sont fermées et tenues par un témoin : le chemin d'un événement (capture -> cible -> remontée, target, closest, preventDefault, stopPropagation, ${cables.length} nœuds de la page réellement câblés), l'attribut « disabled » et son sélecteur, le balisage posé en bloc (sous-arbre, attributs de données, entités, children != childNodes, ${noeudsDeLaPage.length} éléments de la page analysés par le même lecteur dont ${parBloc} porteurs d'un attribut de données), l'absence d'un identifiant (null, contrôle positif sur « ${UN_ID_DE_LA_PAGE} », garde de pose qui pose UNE fois) et les attributs de données dans les deux sens. Chacune a son témoin NÉGATIF — le comportement d'avant reconstitué à la main, que le même vérificateur voit. Ce que ce témoin NE tient PAS : la sixième cécité, la mise en page, qui ne se ferme pas dans un simulacre et que la section 0 DÉCLARE.`);
}

// ---------------------------------------------------------------------------------------------
// 2. LE VERDICT EST RENDU — panneau Système sur des objets fabriqués.
// ---------------------------------------------------------------------------------------------
const { rendreSysteme, lireMesure } = await import(pathToFileURL(path.join(WEB, "system.js")).href);

// (a) TOUT ILLISIBLE — chaque famille d'émission du démon, avec une cause de l'ensemble fermé.
const illisible = (cause, detail) => ({ verdict: "illisible", cause, detail });
const poser = (obj, cle, m) => { if (m.verdict === "lu") obj[cle] = m.valeur; obj[cle + "_verdict"] = m.verdict; obj[cle + "_cause"] = m.cause; if (m.detail) obj[cle + "_detail"] = m.detail; return obj; };
const mA = {
  ts: 1000, version: "x", schema_version: 1, uptime_s: 10,
  process: { verdict: "illisible", cause: "source_absente", detail: "/proc/self/stat : absent" },
  // Une VALEUR à côté du verdict illisible : un chiffre résiduel ne doit JAMAIS passer devant le mot.
  ingest: poser({ events_total: 5, events_1h: 1, queue_depth: 42 }, "queue_depth", illisible("source_refusee", "spool : accès refusé")),
  search: { requests_total: 0, p50_ms: 0, p95_ms: 0, samples: 0 },
  scheduler: poser(poser({ rule_ticks_total: 3, rule_last_tick: 990 }, "regles_abandons", illisible("forme_inconnue", "regles : liste illisible")), "rapports_abandons", { verdict: "lu", valeur: 2, cause: "aucune" }),
  db: poser({}, "size_bytes", illisible("source_illisible", "stat : E/S")),
  host: poser({}, "identity", illisible("source_absente", "/etc/hostname : absent")),
  alerts_open: 0, http: { requests_total: 1, responses_5xx_total: 0 },
};
const hA = {
  posture: "yellow",
  components: [
    poser({ component: "store", state: "green", detail: "disque données 10% utilisé" }, "db_size_bytes", illisible("source_illisible", "stat : E/S")),
    poser({ component: "detection", state: "yellow", detail: "scheduler actif" }, "abandons_dernier_tick", { verdict: "lu", valeur: 4, cause: "aucune" }),
  ],
};
const wrapA = new Element("div");
rendreSysteme(wrapA, mA, hA);
const tuiles = (wrap) => wrap.children.find((c) => c.classList.contains("sys-grid")).children;
const tuile = (wrap, label) => tuiles(wrap).find((t) => t.children.some((c) => c.classList.contains("sys-tile-l") && c.textContent === label));
for (const [label, cause] of [["CPU cumulé", "source absente"], ["RSS mémoire", "source absente"], ["File spool", "accès refusé"], ["Taille base", "source illisible"], ["Identité hôte", "source absente"]]) {
  const t = tuile(wrapA, label);
  exiger(t, `(a) tuile « ${label} » absente du panneau`);
  if (!t) continue;
  const v = t.children.find((c) => c.classList.contains("sys-tile-v")).textContent;
  exiger(v === "NON LISIBLE", `(a) « ${label} » : verdict illisible rendu « ${v} » au lieu de l'état distinct « NON LISIBLE »`);
  exiger(v !== "0" && v !== "" && v !== "—" && !/^0(\.0)? /.test(v), `(a) « ${label} » : rendu aplati en « ${v} »`);
  exiger(t.classList.contains("sys-illisible"), `(a) « ${label} » : la tuile ne porte pas la classe d'état sys-illisible`);
  exiger(texte(t).includes(cause), `(a) « ${label} » : la cause « ${cause} » n'est pas nommée (texte : « ${texte(t)} »)`);
}
const bilansA = wrapA.children.find((c) => c.classList.contains("sys-bilans"));
exiger(bilansA, "(a) aucun bloc de bilans de boucles rendu");
if (bilansA) {
  const tb = texte(bilansA);
  exiger(/regles.*TICK AVEUGLE — forme non reconnue/s.test(tb), `(a) bilan de la boucle « regles » : tick aveugle non rendu comme tel (texte : « ${tb} »)`);
  exiger(/rapports.*2 abandon/s.test(tb), `(a) bilan de la boucle « rapports » : 2 abandons non visibles (texte : « ${tb} »)`);
  const lignes = bilansA.children.filter((c) => c.classList.contains("kv"));
  exiger(lignes.length === 2, `(a) ${lignes.length} ligne(s) de bilan au lieu de 2 : les boucles ne sont pas découvertes sur les clés publiées`);
}
const compsA = wrapA.children.find((c) => c.classList.contains("sys-comps"));
const ligneComp = (wrap, nom) => wrap.children.find((c) => c.classList.contains("sys-comps")).children.find((r) => r.children.some((x) => x.textContent === nom));
const store = ligneComp(wrapA, "store");
exiger(store && /taille base : NON LISIBLE \(source illisible\)/.test(texte(store)), `(a) composant store : taille de base illisible invisible à côté de l'état (texte : « ${store && texte(store)} »)`);
const det = ligneComp(wrapA, "detection");
exiger(det && /abandons du dernier tick : 4/.test(texte(det)), `(a) composant detection : 4 abandons invisibles (texte : « ${det && texte(det)} »)`);
void compsA;

// (b) TOUT LU — la valeur s'affiche, y compris un VRAI zéro, et aucun état d'erreur ne paraît.
const lu = (valeur) => ({ verdict: "lu", valeur, cause: "aucune" });
const mB = {
  ts: 1000, version: "x", schema_version: 1, uptime_s: 10,
  process: { cpu_seconds: 12.34, rss_bytes: 2048, verdict: "lu", cause: "aucune" },
  ingest: poser({ events_total: 5, events_1h: 1 }, "queue_depth", lu(0)),
  search: { requests_total: 0, p50_ms: 0, p95_ms: 0, samples: 0 },
  scheduler: poser({ rule_ticks_total: 3, rule_last_tick: 990 }, "regles_abandons", lu(0)),
  db: poser({}, "size_bytes", lu(3 * 1048576)),
  host: poser({}, "identity", { verdict: "lu", valeur: undefined, cause: "aucune" }),
  alerts_open: 0, http: { requests_total: 1, responses_5xx_total: 0 },
};
const hB = { posture: "green", components: [poser({ component: "store", state: "green", detail: "ok" }, "db_size_bytes", lu(10))] };
const wrapB = new Element("div");
rendreSysteme(wrapB, mB, hB);
for (const [label, attendu] of [["CPU cumulé", "12.3 s"], ["RSS mémoire", "2.0 Ko"], ["File spool", "0"], ["Taille base", "3.0 Mo"], ["Identité hôte", "lue"]]) {
  const t = tuile(wrapB, label);
  exiger(t, `(b) tuile « ${label} » absente du panneau`);
  if (!t) continue;
  const v = t.children.find((c) => c.classList.contains("sys-tile-v")).textContent;
  exiger(v === attendu, `(b) « ${label} » lue : rendu « ${v} » au lieu de « ${attendu} » — une version qui dirait toujours « non lisible » passerait le témoin (a) sans rien prouver`);
  exiger(!t.classList.contains("sys-illisible") && !texte(t).includes("NON LISIBLE"), `(b) « ${label} » lue : porte tout de même l'état illisible`);
}
const bilansB = wrapB.children.find((c) => c.classList.contains("sys-bilans"));
exiger(bilansB && /regles0$/.test(texte(bilansB).replace(/^.*boucle de fond/s, "")), `(b) bilan « regles » lu à zéro : doit rendre un VRAI zéro (texte : « ${bilansB && texte(bilansB)} »)`);
const storeB = ligneComp(wrapB, "store");
exiger(storeB && !/NON LISIBLE|non publié/.test(texte(storeB)), `(b) composant store lu : porte tout de même un état d'erreur (texte : « ${storeB && texte(storeB)} »)`);

// (c) RIEN DE PUBLIÉ — troisième état, distinct des deux autres (pas encore de tick, clé absente).
const mC = { ...mB, scheduler: { rule_ticks_total: 0 }, host: {}, db: {} };
const wrapC = new Element("div");
rendreSysteme(wrapC, mC, { posture: "green", components: [] });
const tC = tuile(wrapC, "Taille base");
exiger(tC && tC.children.find((c) => c.classList.contains("sys-tile-v")).textContent === "non publié", `(c) grandeur jamais publiée : rendu « ${tC && texte(tC)} » au lieu de « non publié »`);
exiger(/aucun bilan publié/.test(texte(wrapC.children.find((c) => c.classList.contains("sys-bilans")))), "(c) aucun bilan de boucle : le démarrage n'est pas dit");

// Le lecteur lui-même : un verdict NON lu l'emporte sur une valeur présente — c'est l'aplatissement
// que la garde nomme, et il ne doit pas pouvoir se reconstruire ici.
exiger(lireMesure({ x: 0, x_verdict: "illisible", x_cause: "source_absente" }, "x").verdict === "illisible", "lireMesure : une valeur présente à côté d'un verdict illisible a été prise pour une lecture");
// La propriété « le verdict l'emporte sur une valeur présente » est tenue DEUX fois (le lecteur retire la
// valeur, le rendu ne l'affiche que sur `lu`) : une mutation de l'un seul ne change pas le DOM. Cette
// assertion tient le lecteur SEUL, pour que la première ligne de défense ait son propre témoin.
exiger(lireMesure({ x: 42, x_verdict: "illisible", x_cause: "source_absente" }, "x").valeur === undefined, "lireMesure : la valeur 42 traverse à côté d'un verdict illisible — seul le rendu la retenait encore");
exiger(lireMesure({ x: 0, x_verdict: "lu", x_cause: "aucune" }, "x").valeur === 0, "lireMesure : un vrai zéro lu a été perdu");
exiger(lireMesure({ x_verdict: "inconnu", x_cause: "aucune" }, "x").verdict === "inconnu", "lireMesure : un mot de verdict inconnu du client a été rangé du côté « lu »");

// ---------------------------------------------------------------------------------------------
// 3. UN PLAYBOOK LIVRÉ ET UN RUNBOOK CRÉÉ RENDENT PAR LE MÊME CHEMIN (`P11.2-a`, `P11.2-b`).
//    Les deux lignes sortent de la même fabrique (`producer_ui.js`) : même classe de ligne, même
//    interrupteur qui porte le MOT de son état et la phrase de sa conséquence, même badge d'origine
//    (le codage inverse de `runbook.managed` est normalisé à la frontière), mêmes classes de bouton —
//    aucune classe sans règle CSS (`ghost`, `primary`). Le témoin inverse (ON <-> OFF) interdit qu'un
//    interrupteur qui dirait toujours le même mot passe.
// ---------------------------------------------------------------------------------------------
{
  const { pbRow } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const { rbRow } = await import(pathToFileURL(path.join(WEB, "runbooks.js")).href);
  const livre = { id: 1, name: "SSH CVE (livré)", enabled: false, query: "search source=sshd | stats count by src_ip", is_soql: true, action_kind: "ban_ip", consequence: "bannit l'IP source pendant 4 h (témoin)", interval_s: 300, window_s: 3600, managed: 0 };
  const cree = { id: 7, key: "custom-x", name: "Runbook créé", match_kind: "tactic", match_key: "initial-access", description: "", managed: 0, active: true, steps: 3 };
  const ligneP = pbRow(livre, "observe");
  const ligneR = rbRow(cree);
  const signature = (row) => row.children.filter((c) => c.tagName !== "BUTTON").map((c) => c.className).join(" | ");
  exiger(ligneP.classList.contains("rulerow") && ligneR.classList.contains("rulerow"), `(3) les deux lignes ne portent pas la classe partagée rulerow (${ligneP.className} / ${ligneR.className})`);
  exiger(signature(ligneP) === signature(ligneR), `(3) structure différente entre playbook livré et runbook créé :\n  ${signature(ligneP)}\n  ${signature(ligneR)}`);
  const interrupteur = (row) => row.children.find((c) => c.classList.contains("producer-switch"));
  const sp = interrupteur(ligneP), sr = interrupteur(ligneR);
  exiger(sp && sr, "(3) l'interrupteur partagé manque sur l'une des deux lignes");
  if (sp && sr) {
    exiger(/\bOFF\b/.test(texte(sp)) && !/\bON\b/.test(texte(sp)), `(3) playbook livré désactivé : l'interrupteur ne dit pas OFF (« ${texte(sp)} »)`);
    exiger(texte(sp).includes("bannit l'IP source pendant 4 h"), `(3) la conséquence servie par le démon n'est pas rendue à côté de l'état (« ${texte(sp)} »)`);
    exiger(texte(sp).includes("Observation") && texte(sp).includes("PROPOSÉ"), `(3) le mode courant (Observation : proposé, pas exécuté) n'est pas dit (« ${texte(sp)} »)`);
    exiger(/\bON\b/.test(texte(sr)) && !/\bOFF\b/.test(texte(sr)), `(3) runbook créé actif : l'interrupteur ne dit pas ON (« ${texte(sr)} »)`);
  }
  const badge = (row) => { const n = row.children.find((c) => c.classList.contains("rulename")); return n && n.children.find((c) => c.classList.contains("mgbadge")); };
  exiger(badge(ligneP) && badge(ligneP).textContent === "builtin", `(3) playbook livré : badge d'origine « ${badge(ligneP) && badge(ligneP).textContent} » au lieu de builtin`);
  exiger(badge(ligneR) && badge(ligneR).textContent === "perso", `(3) runbook créé (runbook.managed=0 = custom) : badge « ${badge(ligneR) && badge(ligneR).textContent} » au lieu de perso — le codage inverse n'est pas normalisé`);
  const classesBoutons = (row) => row.children.filter((c) => c.tagName === "BUTTON").map((c) => c.className);
  // « Sans règle CSS » est DÉRIVÉ de style.css, SANS EXCEPTION (P11.4-b : les boutons de ligne portent
  // `btn btn-sm`). `crud-btn` et `mg-nodel` étaient nommés ici faute d'être dessinés par la feuille : leurs
  // règles d'état vivaient dans le <style> en ligne d'index.html, que cet instrument ne lit pas (P11.4-j).
  // Elles sont maintenant dans style.css — le prédicat n'énumère plus aucun nom.
  const css = readFileSync(path.join(WEB, "style.css"), "utf8");
  const aRegle = (k) => new RegExp("\\." + k + "(?![\\w-])").test(css);
  const horsCharte = [...classesBoutons(ligneP), ...classesBoutons(ligneR)].filter((c) => c.split(/\s+/).some((k) => k && !aRegle(k)));
  exiger(horsCharte.length === 0, `(3) bouton(s) à classe sans règle CSS : ${horsCharte.join(", ")}`);
  exiger(classesBoutons(ligneR).length >= 3 && classesBoutons(ligneP).length >= 3, "(3) l'une des lignes n'a pas ses boutons d'action");
  // Témoin inverse : le mot suit l'état dans les deux familles.
  const sp2 = interrupteur(pbRow({ ...livre, enabled: true }, "active"));
  const sr2 = interrupteur(rbRow({ ...cree, active: false }));
  exiger(sp2 && /\bON\b/.test(texte(sp2)) && texte(sp2).includes("EXÉCUTÉ"), `(3) playbook ON en mode Actif : « ${sp2 && texte(sp2)} »`);
  exiger(sr2 && /\bOFF\b/.test(texte(sr2)), `(3) runbook désactivé : « ${sr2 && texte(sr2)} »`);
}

// ---------------------------------------------------------------------------------------------
// 4. LA LISTE DES ALERTES A UNE SEULE BARRE D'ACTIONS (`P11.1-b`, `P11.1-c`). Plate / Règle / Hôte /
//    Technique sont des TRIS ; la barre est rendue par UNE fonction pure sur le modèle {tri, portée,
//    hors case, facettes}. Témoin : sur TOUTES les combinaisons — les deux facettes comprises, sur les
//    quatre tris et les deux portées — le même jeu d'actions est présent ; une action impossible est
//    DÉSACTIVÉE avec sa raison, jamais absente. Depuis que le démon sert le filtre `source`, AUCUNE action
//    n'est désactivée au motif d'une facette : sous la facette source, tris et portée restent actifs.
//    Témoin inverse : sans facette l'acquittement est global, sous une facette il ne porte que sur les
//    alertes affichées. Et le chip de la facette source dit l'objet, la portée et l'étendue des dates (la
//    cloche d'une source).
// ---------------------------------------------------------------------------------------------
{
  const { alertActionBarHtml, alertListModel } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const attrs = (html, re) => [...html.matchAll(re)].map((m) => m[1]).sort();
  const boutons = (html) => [...html.matchAll(/<button\b([^>]*)>/g)].map((m) => m[1]);
  const signature = (html) => {
    const views = attrs(html, /data-g="([a-z]*)"/g).join(",");
    const acts = attrs(html, /data-act="([a-z-]+)"/g).filter((a) => !a.startsWith("clear-")).map((a) => (a.startsWith("ack") ? "ack" : a)).join(",");
    return `${views} / ${acts} / export:${html.includes("alertbar-export")}`;
  };
  const modeles = [];
  for (const view of ["", "rule", "host", "mitre"]) for (const scopeAll of [false, true]) for (const uncased of [true, false]) for (const facette of ["", "mitre", "source"]) {
    modeles.push({ view, scopeAll, uncased, mitre: facette === "mitre" ? "T1046" : "", source: facette === "source" ? "k8s" : "" });
  }
  exiger(modeles.length === 48, `(4) instrument : ${modeles.length} combinaisons du modèle au lieu de 48 (4 tris × 2 portées × 2 hors case × 3 facettes)`);
  const charges = { count: 3, countLabel: "3 alerte(s)", ackableIds: [1, 2, 3] };
  const signatures = new Set(modeles.map((m) => signature(alertActionBarHtml(m, charges))));
  exiger(signatures.size === 1, `(4) ${signatures.size} jeux d'actions différents selon la vue au lieu d'un seul :\n  ${[...signatures].join("\n  ")}`);
  exiger([...signatures][0].startsWith(",host,mitre,rule / ack,scope,uncased / export:true"), `(4) jeu d'actions inattendu : ${[...signatures][0]}`);
  // AUCUN tri ni portée n'est désactivé au motif d'une facette (P11.1-b : le filtre source est servi par le
  // démon). Sur les 48 combinaisons avec des alertes actives affichées, les seuls boutons désactivés possibles
  // sont ceux de l'acquittement par liste en vue groupée (rien d'affiché à acquitter) — jamais un tri, jamais
  // la portée, jamais « hors case ».
  const desactivesHorsAck = (html) => boutons(html).filter((b) => /\bdisabled\b/.test(b) && !/data-act="ack/.test(b));
  const trisOuPorteeDesactives = modeles.map((m) => [m, desactivesHorsAck(alertActionBarHtml(m, charges))]).filter(([, d]) => d.length);
  exiger(trisOuPorteeDesactives.length === 0, `(4) un tri, la portée ou « hors case » est désactivé sous une facette : ${trisOuPorteeDesactives.map(([m, d]) => JSON.stringify(m) + " -> " + d.join(" | ")).join("\n  ")}`);
  // Sous la facette source, vue plate : rien n'est désactivé, et le chip dit l'objet, la portée, l'étendue.
  const sousSource = alertActionBarHtml({ view: "", scopeAll: false, uncased: false, mitre: "", source: "k8s" }, { ...charges, sourceSpan: { from: 1_700_000_000, to: 1_700_090_000 } });
  const desactives = boutons(sousSource).filter((b) => /\bdisabled\b/.test(b));
  exiger(desactives.length === 0, `(4) sous la facette source, ${desactives.length} bouton(s) désactivé(s) au lieu de 0 : ${desactives.join(" | ")}`);
  exiger(!/côté client/.test(sousSource), "(4) la barre parle encore d'un filtre évalué côté client : la raison n'a plus d'objet");
  exiger(!/data-act="ack-all"/.test(sousSource) && /data-act="ack-shown"/.test(sousSource) && /Acquitter les 3 affichée/.test(sousSource), "(4) sous une facette, l'acquittement doit porter sur les 3 alertes affichées, jamais être global");
  exiger(/Source : /.test(sousSource) && /3 alerte\(s\) active\(s\) imputée\(s\) à cette source, toutes dates \(du .+ au .+\)/.test(sousSource) && /sans lien avec sa fraîcheur/.test(sousSource), `(4) le chip de la facette source ne dit pas objet + portée + étendue des dates + indépendance de la fraîcheur : ${sousSource.match(/Source : .*?<\/span><button/)?.[0]}`);
  // Facette source sur un tri groupé, portée « tous statuts » : le tri et la portée sont ACTIFS (marqués « on »,
  // jamais `disabled`) et le chip compte des groupes, tous statuts.
  const sourceGroupee = alertActionBarHtml({ view: "rule", scopeAll: true, uncased: true, mitre: "", source: "k8s" }, { count: 2, countLabel: "2 groupe(s)", ackableIds: [] });
  // Le motif ne fige plus l'ORDRE des attributs (`P11.4-i` a inséré `aria-pressed` entre la classe et
  // `data-g`) : il exige la classe « on » et l'absence de `disabled` SUR LE MÊME bouton, ce qui est la
  // propriété visée — un motif d'ordre aurait rougi sur un ajout d'attribut sans rien dire de l'état.
  const boutonAvec = (html, motif) => (html.match(new RegExp(`<button[^>]*${motif}[^>]*>`)) || [])[0] || "";
  const btnTriRegle = boutonAvec(sourceGroupee, 'data-g="rule"'), btnPortee = boutonAvec(sourceGroupee, 'data-act="scope"');
  exiger(/class="agseg on"/.test(btnTriRegle) && !/\bdisabled\b/.test(btnTriRegle) && /class="agscope on"/.test(btnPortee) && !/\bdisabled\b/.test(btnPortee), `(4) sous la facette source, le tri « Règle » et la portée « tous statuts » doivent être actifs, sans \`disabled\` : ${btnTriRegle} ${btnPortee}`);
  exiger(/2 groupe\(s\) d'alertes \(tous statuts\) imputée\(s\) à cette source/.test(sourceGroupee), `(4) le chip de la facette source en vue groupée ne compte pas des groupes tous statuts : ${sourceGroupee.match(/Source : .*?<\/span><button/)?.[0]}`);
  // Témoin inverse : sans facette, sur les actives, l'acquittement est GLOBAL et le dit.
  const sansFacette = alertActionBarHtml({ view: "rule", scopeAll: false, uncased: true, mitre: "", source: "" }, { count: 9, countLabel: "9 groupe(s)", ackableIds: [] });
  exiger(/data-act="ack-all"[^>]*title="[^"]*y compris celles hors de cette page/.test(sansFacette) && !/\bdisabled\b[^>]*>[^<]*Tout acquitter/.test(sansFacette), "(4) sans facette, « Tout acquitter » doit être global, actif, et dire qu'il dépasse la page");
  // Vue groupée sous facette technique : rien d'affiché à acquitter par liste -> désactivé AVEC la raison.
  const groupeFacette = alertActionBarHtml({ view: "host", scopeAll: true, uncased: false, mitre: "T1046", source: "" }, { count: 2, countLabel: "2 groupe(s)", ackableIds: [] });
  exiger(/data-act="ack-shown" disabled[^>]*title="[^"]*dépliez un groupe/.test(groupeFacette), "(4) en vue groupée sous facette, l'acquittement doit être désactivé avec la raison « dépliez un groupe »");
  // Le modèle lit l'état partagé, et « hors case » vaut oui par défaut (champ absent).
  S.alertGroupBy = "host"; S.alertGroupAll = true; S.alertMitreFilter = "T1110"; S.alertSourceFilter = ""; delete S.alertUncased;
  const m = alertListModel();
  exiger(m.view === "host" && m.scopeAll === true && m.uncased === true && m.mitre === "T1110" && m.source === "", `(4) alertListModel ne reflète pas l'état : ${JSON.stringify(m)}`);
  S.alertUncased = false;
  exiger(alertListModel().uncased === false, "(4) alertListModel : « hors case » posé à faux n'est pas lu");
  S.alertGroupBy = ""; S.alertGroupAll = false; S.alertMitreFilter = ""; S.alertUncased = true;
}

// ---------------------------------------------------------------------------------------------
// 4. LA RECHERCHE ET LA COUVERTURE ATT&CK (`P11.6-a`, `P11.9-a`, `P11.9-b`, `P11.9-c`).
//    (a) Une technique sans nom se DIT : « nom inconnu », jamais une cellule vide. Le nom SERVI est la
//        seule source (`P11.6-c`) : sans lui la cellule dit le mot, elle ne devine pas.
//    (b) L'éditeur de requête ne réécrit JAMAIS `!=` : une séquence de frappe réelle (regex avec `|`,
//        puis espace, puis Entrée/Tab) laisse le « différent » en place — et le témoin inverse prouve
//        que la complétion est bien VIVANTE sur cet éditeur (Tab accepte une suggestion). La cause
//        mesurée du constat est la ligature `!=` de la police (calt) : l'éditeur la coupe, et c'est tenu.
//    (c) La palette « Modèles » liste mes modèles (modifiables, supprimables) ET les modèles livrés
//        (copiables), avec ses états vides et indisponibles nommés.
//    (d) Le badge de troncature dit ce qui s'est passé et comment continuer selon le contexte de
//        feuilletage (saut direct par numéro de page vs parcours par curseur vs total).
// ---------------------------------------------------------------------------------------------
{
  const { techniqueCell, techniqueDisplayName, NOM_INCONNU } = await import(pathToFileURL(path.join(WEB, "attack.js")).href);
  // (a) nom servi par le démon
  let c = techniqueCell({ tid: "T1110", name: "Brute Force", covered: true, rule_count: 1, alert_count: 0 }, 1);
  exiger(texte(c).includes("Brute Force"), `(4a) nom servi non rendu : « ${texte(c)} »`);
  // nom ABSENT (null) et identifiant hors catalogue -> le MOT, pas un vide
  c = techniqueCell({ tid: "T9999", name: null, covered: false }, 1);
  const nomEl = c.children.find((x) => x.classList.contains("attack-tname"));
  exiger(nomEl && nomEl.textContent === NOM_INCONNU, `(4a) technique hors catalogue : nom rendu « ${nomEl && nomEl.textContent} » au lieu de « ${NOM_INCONNU} »`);
  exiger(nomEl && nomEl.classList.contains("attack-tname-inconnu"), "(4a) la cellule sans nom ne porte pas sa classe d'état");
  exiger(c.title.includes(NOM_INCONNU) && c.title.includes("hors du catalogue"), `(4a) l'infobulle ne dit pas pourquoi le nom manque : « ${c.title} »`);
  // sous-technique sans nom servi -> le MOT, pas une devinette (`P11.6-c` : plus de table locale ici)
  exiger(techniqueDisplayName({ tid: "T1110.003" }) === null, `(4a) la matrice devine encore un nom sans le démon : « ${techniqueDisplayName({ tid: "T1110.003" })} » — un second porteur du catalogue`);
  exiger(techniqueDisplayName({ tid: "T1110", name: "   " }) === null, "(4a) un nom vide servi doit compter comme absent, et l'absence se DIT");
  exiger(techniqueDisplayName({ tid: "T9999" }) === null, "(4a) hors catalogue -> null (la cellule dit le mot), pas une chaîne");

  // (b) l'éditeur — objet fabriqué qui porte la sélection et dispatch ses écouteurs.
  const { primeCompletionMeta, initSoqlComplete } = await import(pathToFileURL(path.join(WEB, "soql_complete.js")).href);
  class Editeur extends Element {
    constructor() { super("textarea"); this.selectionStart = 0; this.selectionEnd = 0; this._ecouteurs = {}; }
    addEventListener(type, fn) { (this._ecouteurs[type] = this._ecouteurs[type] || []).push(fn); }
    dispatchEvent(ev) { (this._ecouteurs[ev.type] || []).forEach((f) => f(ev)); return true; }
    setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
  }
  const schema = {
    base_keywords: ["search", "metric"], commands: ["where", "stats", "table", "sort"],
    stats_functions: ["count", "sum"], eval_functions: ["if"], operators: ["=", "!=", ">", "<", ">=", "<=", "=~", ":"],
    fields: { core: ["ts", "host", "source", "message", "status", "severity"], extended: [] },
    values: { severity: [{ value: 1, label: "low" }, { value: 3, label: "high" }], source: ["sshd", "web"] },
  };
  primeCompletionMeta(schema, []);
  const ed = new Editeur();
  const getById = document.getElementById;
  document.getElementById = (id) => (id === "sql" ? ed : new Element("div"));
  initSoqlComplete();
  document.getElementById = getById;
  exiger(ed.dataset.acWired === "1", "(4b) l'éditeur fabriqué n'a pas été câblé par initSoqlComplete");
  exiger(ed.style.fontVariantLigatures === "none", `(4b) les ligatures de police ne sont pas coupées sur l'éditeur (« ${ed.style.fontVariantLigatures} ») : un « != » tapé s'afficherait comme un glyphe barré`);
  const pause = () => new Promise((r) => setTimeout(r, 0));
  const touche = (key) => ({ type: "keydown", key, ctrlKey: false, metaKey: false, preventDefault() {} });
  const taper = async (texte) => {
    for (const ch of texte) {
      ed.dispatchEvent(touche(ch));
      const p = ed.selectionStart;
      ed.value = ed.value.slice(0, p) + ch + ed.value.slice(p);
      ed.setSelectionRange(p + 1, p + 1);
      ed.dispatchEvent({ type: "input" });
      await pause();
    }
  };
  const sequences = [
    'search message=~"(foo|bar)" status!=200',
    'search message=~"^a.*b$" severity!=3',
    'search host!=db | where source!=sshd',
  ];
  for (const seq of sequences) {
    ed.value = ""; ed.setSelectionRange(0, 0);
    await taper(seq);
    exiger(ed.value === seq, `(4b) la frappe seule a altéré le texte : « ${ed.value} »`);
    await taper(" ");
    exiger(ed.value === seq + " ", `(4b) l'espace après « ${seq} » a réécrit le texte : « ${ed.value} »`);
    const avantEntree = ed.value;
    ed.dispatchEvent(touche("Enter")); await pause();
    exiger(ed.value.includes("!="), `(4b) Entrée après l'espace a fait disparaître « != » : « ${ed.value} »`);
    const nbDiff = (ed.value.match(/!=/g) || []).length, nbAttendu = (avantEntree.match(/!=/g) || []).length;
    exiger(nbDiff === nbAttendu, `(4b) le nombre de « != » a changé après Entrée (${nbAttendu} -> ${nbDiff}) : « ${ed.value} »`);
  }
  // Témoin INVERSE : la complétion est vivante sur cet éditeur — Tab sur « sever » insère « severity ».
  ed.value = ""; ed.setSelectionRange(0, 0);
  await taper("search sever");
  ed.dispatchEvent(touche("Tab")); await pause();
  exiger(ed.value.startsWith("search severity"), `(4b) témoin inverse : Tab n'a pas complété « sever » (« ${ed.value} ») — l'éditeur fabriqué n'est pas relié à la complétion, les témoins précédents ne prouvent rien`);

  // (c) la palette des modèles
  const { renderTemplatePalette } = await import(pathToFileURL(path.join(WEB, "soql_complete.js")).href);
  const appels = [];
  const actions = { load: (m) => appels.push(["load", m]), edit: (m) => appels.push(["edit", m]), remove: (m) => appels.push(["remove", m]), copy: (m) => appels.push(["copy", m]) };
  const mien = { id: 1, name: "Mon modèle", soql: "search a" }, livre = { id: "lib-x", title: "Livré", soql: "search b", keywords: ["b"] };
  const liste = new Element("div");
  renderTemplatePalette(liste, "", [mien], [livre], actions);
  const t = texte(liste);
  exiger(t.includes("Mes modèles") && t.includes("Mon modèle") && t.includes("Modèles livrés") && t.includes("Livré"), `(4c) palette : sections ou lignes absentes (« ${t} »)`);
  const lignes = liste.children.filter((x) => x.classList.contains("soql-tpl-item"));
  exiger(lignes.length === 2, `(4c) ${lignes.length} ligne(s) au lieu de 2`);
  const titres = (row) => row.children.filter((x) => x.tagName === "BUTTON").map((x) => x.title);
  exiger(titres(lignes[0]).includes("Modifier ce modèle") && titres(lignes[0]).includes("Supprimer ce modèle"), `(4c) un modèle personnel ne porte pas modifier + supprimer : ${titres(lignes[0]).join(" / ")}`);
  exiger(titres(lignes[1]).some((x) => x.startsWith("Copier dans mes modèles")) && !titres(lignes[1]).includes("Supprimer ce modèle"), `(4c) un modèle livré doit se copier et ne pas se supprimer : ${titres(lignes[1]).join(" / ")}`);
  renderTemplatePalette(liste, "", [], [livre], actions);
  exiger(texte(liste).includes("Aucun modèle personnel"), "(4c) l'état vide des modèles personnels n'est pas nommé");
  renderTemplatePalette(liste, "", null, [livre], actions);
  exiger(texte(liste).includes("indisponibles"), "(4c) un chargement échoué des modèles personnels n'est pas distingué d'une liste vide");
  renderTemplatePalette(liste, "b", [mien], [livre], actions);
  exiger(!texte(liste).includes("Mon modèle") && texte(liste).includes("Livré"), "(4c) le filtre ne s'applique pas aux deux groupes");

  // (d) le badge de troncature selon le contexte de feuilletage
  const { truncationBadge } = await import(pathToFileURL(path.join(WEB, "viz.js")).href);
  const saut = truncationBadge({ truncated: true }, { keyset: true, saut: true, page: 7 });
  exiger(/page sautée/.test(saut[1]) && /partiel/.test(saut[1]), `(4d) page sautée : libellé « ${saut[1]} »`);
  exiger(saut[2].includes("◀") && saut[2].includes("curseur") && /page 1/.test(saut[2]), `(4d) page sautée : l'infobulle ne dit pas comment continuer (« ${saut[2]} »)`);
  const curseur = truncationBadge({ truncated: true }, { keyset: true, saut: false, page: 2 });
  exiger(/plafond/.test(curseur[1]) && /page plus petite/.test(curseur[2]), `(4d) page par curseur tronquée : « ${curseur[1]} / ${curseur[2]} »`);
  const total = truncationBadge({ truncated: true }, null);
  exiger(total[1] === "tronqué — ampleur inconnue" && /Resserrez/.test(total[2]), `(4d) hors feuilletage : « ${total[1]} / ${total[2]} »`);
  const chiffre = truncationBadge({ truncated: true, topn_ecartes: 40, topn_total: 100 }, { keyset: true, saut: true, page: 3 });
  exiger(/40.*écartés.*40 %/.test(chiffre[1]), `(4d) une ampleur CHIFFRÉE doit l'emporter sur le contexte : « ${chiffre[1]} »`);
}

// ---------------------------------------------------------------------------------------------
// 5. L'INVENTAIRE DES SOURCES (`P11.3-a`) — attendue par construction / inattendue / marquée, et le
//    geste d'acquittement offert à l'éditeur, rendus sur des objets fabriqués.
// ---------------------------------------------------------------------------------------------
{
  const { renderSourcesInventory } = await import(pathToFileURL(path.join(WEB, "sources.js")).href);
  // parcours du tableau rendu par pagedList : lignes <tr> du <tbody>, cellules <td>, texte par cellule.
  const lignesDe = (wrap) => {
    const out = [];
    const marcher = (el) => { if (!el || !el.children) return; if (el.tagName === "TR" && el.parentNode && el.parentNode.tagName === "TBODY") out.push(el); el.children.forEach(marcher); };
    marcher(wrap);
    return out;
  };
  const celluleTexte = (tr, i) => texte(tr.children[i]);
  const enTetes = (wrap) => { let th = []; const marcher = (el) => { if (!el || !el.children) return; if (el.tagName === "THEAD") th = el.children[0].children.map((x) => texte(x)); el.children.forEach(marcher); }; marcher(wrap); return th; };
  const inventaire = {
    ok: true, pipeline_fresh: true, sources: [
      // livrée par ce dépôt : déclarée par construction, la raison nomme le fichier ; calme, et sa cadence
      // reste DÉCLARABLE (aucune sonde n'en déclare) -> l'éditeur doit se voir offrir le geste.
      { source: "portprobe", expected: true, unexpected: false, in_collectors: true, declaree_par: "ce dépôt", raison_attendue: "émise par un fichier livré (collectors/portprobe.sh)", marquage: null, cadence_declarable: true, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, cadence_par: null, cadence_le: null, observed_interval_s: 72, last_seen: 1000, age_s: 7200, n_24h: 1200, status: "calme" },
      // personne ne l'a déclarée : le signal.
      { source: "derive-deploiement", expected: false, unexpected: true, in_collectors: false, declaree_par: null, raison_attendue: null, marquage: null, cadence_declarable: true, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, cadence_par: null, cadence_le: null, observed_interval_s: 3600, last_seen: 1000, age_s: 3000, n_24h: 24, status: "calme" },
      // déclarée PAR L'EXPLOITANT, avec la cadence qu'il a lui-même déclarée : qui et quand sont rendus.
      { source: "vault-custom", expected: true, unexpected: false, in_collectors: false, declaree_par: "l'exploitant", raison_attendue: "déclarée par eve (ts 1700000000)", marquage: { expected: true, updated_by: "eve", updated: 1700000000 }, cadence_declarable: true, cadence_declaree: "continue", cadence_interval_s: 3600, cadence_capteur: null, cadence_par: "eve", cadence_le: 1700000000, observed_interval_s: 600, last_seen: 1000, age_s: 120, n_24h: 144, status: "frais" },
      // continue déclarée par une SONDE et dépassée : en retard — et la cadence n'y est pas déclarable.
      { source: "auditd", expected: true, unexpected: false, in_collectors: true, declaree_par: "ce dépôt", raison_attendue: "émise par un fichier livré (collectors/auditd.sh)", marquage: null, cadence_declarable: false, cadence_declaree: "continue", cadence_interval_s: 120, cadence_capteur: "audit", cadence_par: null, cadence_le: null, observed_interval_s: 30, last_seen: 1000, age_s: 1200, n_24h: 2880, status: "en_retard" },
    ],
  };
  const ligne = (rows, nom) => rows.find((tr) => celluleTexte(tr, 0).startsWith(nom));
  // (a) LECTEUR (viewer) : verdicts et raisons rendus, aucune colonne d'action.
  document.body.className = "role-viewer";
  const invA = new Element("div");
  renderSourcesInventory(invA, inventaire);
  const lignesA = lignesDe(invA);
  exiger(lignesA.length === 4, `(inventaire) ${lignesA.length} ligne(s) rendue(s) au lieu de 4`);
  const colsA = enTetes(invA);
  exiger(!colsA.includes("Actions"), `(inventaire, viewer) une colonne Actions est offerte à un rôle qui ne peut pas marquer (${colsA.join(", ")})`);
  const lPort = ligne(lignesA, "portprobe"), lDer = ligne(lignesA, "derive-deploiement"), lVc = ligne(lignesA, "vault-custom"), lAud = ligne(lignesA, "auditd");
  exiger(lPort && !celluleTexte(lPort, 0).includes("non déclarée"), "(inventaire) une source LIVRÉE porte le badge « non déclarée » : la dérivation n'est pas lue");
  exiger(lPort && texte(lPort).includes("collectors/portprobe.sh"), `(inventaire) la raison « déclarée par ce dépôt » (fichier livré) n'est pas rendue : « ${lPort && texte(lPort)} »`);
  exiger(lPort && celluleTexte(lPort, 1).includes("ce dépôt"), `(inventaire) la colonne « Déclarée » ne NOMME pas le déclarant : « ${lPort && celluleTexte(lPort, 1)} »`);
  exiger(lDer && celluleTexte(lDer, 0).includes("non déclarée"), "(inventaire) une source que personne n'a déclarée ne porte PAS le badge");
  exiger(lDer && celluleTexte(lDer, 1).includes("personne") && celluleTexte(lDer, 1).includes("aucune déclaration"), `(inventaire) l'absence de déclaration n'est pas dite pour ce qu'elle est : « ${lDer && celluleTexte(lDer, 1)} »`);
  exiger(lVc && !celluleTexte(lVc, 0).includes("non déclarée") && texte(lVc).includes("déclarée par eve"), `(inventaire) la déclaration de l'exploitant (qui) n'est pas rendue : « ${lVc && texte(lVc)} »`);
  exiger(lVc && celluleTexte(lVc, 1).includes("l'exploitant"), `(inventaire) le cinquième déclarant n'est pas nommé : « ${lVc && celluleTexte(lVc, 1)} »`);
  exiger(lVc && celluleTexte(lVc, 2).includes("continu · 60 min") && celluleTexte(lVc, 2).includes("déclarée par eve"), `(inventaire) une cadence déclarée par un humain ne dit pas qui : « ${lVc && celluleTexte(lVc, 2)} »`);
  exiger(lAud && texte(lAud).includes("en retard") && texte(lAud).includes("continu · 2 min"), `(inventaire) « en retard » et la cadence déclarée ne sont pas rendus : « ${lAud && texte(lAud)} »`);
  exiger(lAud && celluleTexte(lAud, 2).includes("sonde « audit »"), `(inventaire) la cadence d'une SONDE ne nomme pas la sonde : « ${lAud && celluleTexte(lAud, 2)} »`);
  exiger(lPort && texte(lPort).includes("calme") && !texte(lPort).includes("retard") && celluleTexte(lPort, 2).includes("aucune cadence déclarée"), `(inventaire) une source sans cadence déclarée, silencieuse 2 h, doit lire « calme » et « aucune cadence déclarée » : « ${lPort && texte(lPort)} »`);
  exiger(!texte(invA).includes("cadence non déclarée"), "(inventaire) une absence de DÉCLARATION est encore présentée comme un défaut de cadence");
  exiger(texte(invA).includes("1 source(s) que personne n'a déclarée"), "(inventaire) le compte des signaux n'est pas rendu en tête");
  exiger(!texte(invA).includes("dégradé"), "(inventaire) le mot « dégradé » survit dans l'inventaire");
  // (b) ÉDITEUR : la colonne Actions existe et offre « marquer attendue » sur le signal, « marquer inattendue » sur l'acquittée.
  document.body.className = "role-editor";
  const invB = new Element("div");
  renderSourcesInventory(invB, inventaire);
  const colsB = enTetes(invB);
  exiger(colsB.includes("Actions"), `(inventaire, editor) aucune colonne Actions : l'éditeur n'a toujours aucune issue (${colsB.join(", ")})`);
  const lignesB = lignesDe(invB);
  const actionsDe = (tr) => { const td = tr.children[tr.children.length - 1]; const out = []; const marcher = (el) => { if (!el || !el.children) return; if (el.tagName === "BUTTON") out.push(texte(el)); el.children.forEach(marcher); }; marcher(td); return out; };
  exiger(actionsDe(ligne(lignesB, "derive-deploiement")).includes("déclarer attendue"), `(inventaire, editor) le signal n'offre pas « déclarer attendue » : ${JSON.stringify(actionsDe(ligne(lignesB, "derive-deploiement")))}`);
  exiger(actionsDe(ligne(lignesB, "vault-custom")).includes("retirer la déclaration"), "(inventaire, editor) une source déclarée n'offre pas le geste inverse (réversibilité)");
  exiger(texte(invB).includes("Actions → « déclarer attendue »"), "(inventaire, editor) l'en-tête ne dit pas à l'éditeur où est le geste");
  // P11.3-c — LE GESTE DE CADENCE N'EST OFFERT QUE LÀ OÙ IL A UN EFFET : le démon REFUSE une déclaration
  // humaine là où une sonde parle, donc offrir le bouton y serait promettre un réglage sans effet.
  exiger(actionsDe(ligne(lignesB, "derive-deploiement")).includes("déclarer la cadence"), `(inventaire, editor) une source sans cadence déclarée n'offre pas de la déclarer : ${JSON.stringify(actionsDe(ligne(lignesB, "derive-deploiement")))}`);
  exiger(!actionsDe(ligne(lignesB, "auditd")).includes("déclarer la cadence"), "(inventaire, editor) le geste de cadence est offert là où une sonde déclare déjà : le démon le refuserait");
  document.body.className = "";
}

// ---------------------------------------------------------------------------------------------
// 6. LA FRAÎCHEUR (`P11.3-b`) — le statut vient du démon ; une périodique dans sa cadence est « frais »
//    ou « calme », jamais « en retard » ; « dégradé » n'existe plus ; les alertes sont un compte.
// ---------------------------------------------------------------------------------------------
{
  const { renderFreshnessDetail, freshState, countStates } = await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const feeds = {
    pipeline_fresh: true,
    // P11.3-d — le PARTAGE des alertes actives, qui doit se retrouver : 2 avec cloche (cloudflare en
    // porte 2, une seule alerte y suffit ici), 1 sans flux, 1 sans imputation enregistrée.
    imputation_des_alertes: { actives: 4, avec_cloche: 2, sans_source_nommee: 1, sans_imputation: 1, jeton_sans_source: "(source indéterminée)" },
    feeds: [
      // périodique (courrier) à 66 min sans cadence déclarée : calme — le cas du constat.
      { kind: "event", name: "mail", status: "calme", age_s: 66 * 60, last_seen: 1000, n_24h: 96, active_alerts: 0, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 900 },
      // périodique DANS sa cadence : frais.
      { kind: "event", name: "kube-rbac", status: "frais", age_s: 600, last_seen: 1000, n_24h: 48, active_alerts: 0, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 1800 },
      // continue déclarée, silence au-delà : en retard, la raison est dite.
      { kind: "event", name: "kube-audit", status: "en_retard", age_s: 1500, last_seen: 1000, n_24h: 5000, active_alerts: 0, cadence_declaree: "continue", cadence_interval_s: 120, cadence_capteur: "kube-audit", observed_interval_s: 17 },
      // frais avec alertes actives : la cloche, pas un état.
      { kind: "event", name: "cloudflare", status: "frais", age_s: 30, last_seen: 1000, n_24h: 3000, active_alerts: 2, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 28 },
      // événementiel, deux jours de calme : calme.
      { kind: "event", name: "yara", status: "calme", age_s: 172800, last_seen: 1000, n_24h: 0, active_alerts: 0, cadence_declaree: "evenementielle", cadence_interval_s: null, cadence_capteur: "yara", observed_interval_s: null },
    ],
  };
  const html = renderFreshnessDetail(feeds);
  const brut = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  exiger(!/dégradé/.test(brut), "(fraîcheur) le mot « dégradé » survit dans le détail");
  exiger(/2 frais/.test(brut) && /2 calme/.test(brut) && /1 en retard/.test(brut), `(fraîcheur) compteurs de tête faux : « ${brut.slice(0, 400)} »`);
  exiger(/1 avec alertes actives/.test(brut), "(fraîcheur) les alertes actives ne sont pas comptées à part en tête");
  exiger(freshState(feeds.feeds[0]) === "calme", `(fraîcheur) le courrier à 66 min lit « ${freshState(feeds.feeds[0])} » au lieu de « calme »`);
  exiger(freshState(feeds.feeds[1]) === "frais", "(fraîcheur) une périodique dans sa cadence ne lit pas « frais »");
  exiger(freshState(feeds.feeds[3]) === "frais", "(fraîcheur) des alertes actives font basculer l'état de collecte");
  exiger(freshState({ status: "warn" }) === "calme" && freshState({ status: "inconnu" }) === "attente", "(fraîcheur) un mot inconnu du client n'est pas rangé du côté calme / attente");
  const sc = countStates(feeds.feeds);
  exiger(sc.frais === 2 && sc.calme === 2 && sc.en_retard === 1 && sc.muet === 0 && sc.alertes === 1, `(fraîcheur) agrégation ${JSON.stringify(sc)}`);
  exiger(/en retard — cadence déclarée dépassée/.test(brut), "(fraîcheur) le groupe « en retard » ne dit pas ce qu'il désigne");
  exiger(/kube-audit[^]*?au-delà de 2 min/.test(brut), `(fraîcheur) la ligne en retard ne nomme pas la cadence dépassée : « ${brut} »`);
  exiger(/mail aucune cadence déclarée/.test(brut) && /yara événementiel — pas de cadence par nature/.test(brut) && /kube-audit continu · 2 min/.test(brut), `(fraîcheur) la cadence déclarée n'est pas rendue à côté du nom : « ${brut} »`);
  // P11.3-d — LA PHRASE DIT CE QUE LA CLOCHE COUVRE ET CE QU'ELLE NE COUVRE PAS, elle n'accuse plus la
  // collecte, et le compte « sans flux » est un PIVOT vers les alertes concernées.
  exiger(/4 alerte\(s\) active\(s\)/.test(brut) && /2 imputée\(s\) à un flux/.test(brut), `(fraîcheur) le partage des alertes actives n'est pas rendu : « ${brut} »`);
  exiger(/sans flux \(normal pour une alerte d'hôte, de règle ou de seuil\)/.test(brut), "(fraîcheur) « sans flux » n'est pas dit pour ce qu'il est, il se lit encore comme un défaut de collecte");
  exiger(/sans imputation enregistrée/.test(brut), "(fraîcheur) la famille que personne ne comptait reste tue");
  exiger(!/aucune cloche de source ne les porte/.test(brut), "(fraîcheur) l'ancienne phrase, qui laissait croire à un trou de collecte, survit");
  exiger(/class="forph"[^>]*data-src="\(source indéterminée\)"/.test(html), `(fraîcheur) le compte « sans flux » n'est pas un pivot vers ces alertes : « ${html.slice(0, 900)} »`);
  exiger(!/fwarn[^>]*>[^<]*alerte\(s\) active/.test(html), "(fraîcheur) la répartition des alertes est peinte comme une anomalie (fwarn)");
  // ... et sans aucune alerte active, RIEN n'est affiché : une phrase sur des cloches inexistantes ne
  // pourrait qu'induire en erreur.
  const sansAlerte = renderFreshnessDetail({ pipeline_fresh: true, imputation_des_alertes: { actives: 0, avec_cloche: 0, sans_source_nommee: 0, sans_imputation: 0, jeton_sans_source: "(source indéterminée)" }, feeds: feeds.feeds }).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  exiger(!/alerte\(s\) active\(s\)/.test(sansAlerte), `(fraîcheur) une répartition est affichée alors qu'aucune alerte n'est active : « ${sansAlerte.slice(0, 300)} »`);
  exiger(/Il ne devient un retard que pour une source dont QUELQU'UN — une sonde du démon ou l'exploitant — DÉCLARE une cadence continue/.test(brut), "(fraîcheur) l'en-tête ne dit plus ce qu'est un retard, ni qui peut le déclarer");
  exiger(!/expected_s|4x|4×/.test(html), "(fraîcheur) la surface dérive encore un retard d'une moyenne observée");
  // pipeline en panne : tout muet, le bandeau rouge.
  const panne = renderFreshnessDetail({ pipeline_fresh: false, feeds: feeds.feeds.map((f) => ({ ...f, status: "muet" })) }).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  exiger(/Ingestion en panne/.test(panne) && /5 muet/.test(panne), "(fraîcheur) l'ingestion en panne n'est pas rendue muette partout");
}

// ---------------------------------------------------------------------------------------------
// 7. LES COMPOSANTS PARTAGÉS DE L'ADMINISTRATION (`P11.4-a`, `P11.4-b`, `P11.5-b`) — une carte se
//    replie par le bouton qui l'a ouverte et ce bouton n'est jamais grisé ; un formulaire de création
//    rendu par un module porte les classes partagées (primaire / secondaire) et aucun bouton nu ; la
//    confirmation partagée REFUSE de se poser sans conséquence nommée, bloque quand on l'écarte, laisse
//    passer quand on la valide.
// ---------------------------------------------------------------------------------------------
{
  const { disclosure, confirmWithConsequence } = await import(pathToFileURL(path.join(WEB, "core.js")).href);
  // (a) dépli : ouvrir, refermer, état du bouton.
  const btn = new Element("button"), panel = new Element("div"); panel.id = "p"; panel.classList.add("hidden");
  const d = disclosure(btn, panel);
  exiger(d && btn.getAttribute("aria-expanded") === "false", "(dépli) le bouton ne porte pas son état fermé à l'armement");
  btn.onclick();
  exiger(!panel.classList.contains("hidden") && !panel.hidden, "(dépli) le premier clic n'ouvre pas la carte");
  exiger(btn.getAttribute("aria-expanded") === "true" && btn.classList.contains("on"), "(dépli) la carte ouverte ne se lit pas sur le bouton");
  exiger(btn.disabled !== true, "(dépli) le bouton est grisé pendant que la carte est ouverte");
  btn.onclick();
  exiger(panel.classList.contains("hidden") && panel.hidden === true, "(dépli) le second clic ne REPLIE pas la carte — c'est le constat de `P11.4-a`");
  exiger(btn.getAttribute("aria-expanded") === "false" && !btn.classList.contains("on"), "(dépli) la carte repliée ne se lit pas sur le bouton");
  // `isOpen`/`open`/`close` sur mesure (plusieurs boutons, un panneau) : le bouton dont le contenu n'est
  // pas affiché n'est pas « ouvert ».
  let contenu = null;
  const b2 = new Element("button"), b3 = new Element("button"), shared = new Element("div");
  const mk = (b, type) => disclosure(b, shared, { isOpen: () => contenu === type, open: () => { contenu = type; }, close: () => { contenu = null; } });
  mk(b2, "http"); mk(b3, "taxii");
  b2.onclick();
  exiger(contenu === "http" && b2.getAttribute("aria-expanded") === "true", "(dépli) ouverture sur mesure");
  b3.onclick();
  exiger(contenu === "taxii", "(dépli) un autre bouton sur le même panneau REMPLACE le contenu au lieu de replier");
  b3.onclick();
  exiger(contenu === null, "(dépli) le bouton dont le contenu est affiché replie au second clic");

  // (b) un formulaire de création rendu par un module : classes partagées, aucun bouton nu.
  const { openDestinationForm } = await import(pathToFileURL(path.join(WEB, "destinations.js")).href);
  const host = new Element("div"); host.id = "destination-form-host";
  const qsAvant = document.querySelector;
  document.querySelector = (sel) => (sel === "#destination-form-host" ? host : new Element("div"));
  try { openDestinationForm(null); } finally { document.querySelector = qsAvant; }
  const boutons = [], parcourir = (el, anc) => { if (!el || !el.children) return; for (const c of el.children) { if (c.tagName === "BUTTON") boutons.push({ el: c, anc: [...anc] }); parcourir(c, [...anc, c]); } };
  parcourir(host, []);
  exiger(boutons.length >= 2, `(classes) le formulaire de destination rend ${boutons.length} bouton(s), au moins 2 attendus`);
  const PARTAGEES = ["btn", "btn-primary", "btn-danger", "btn-link", "picon"];
  const nus = boutons.filter(({ el, anc }) => !PARTAGEES.some((k) => el.classList.contains(k)) && !anc.some((a) => a.classList.contains("rf-actions")));
  exiger(nus.length === 0, `(classes) ${nus.length} bouton(s) NU(s) dans le formulaire de destination : ${nus.map((n) => n.el.textContent).join(", ")} — c'est le constat de \`P11.4-b\``);
  exiger(boutons.some(({ el }) => el.classList.contains("btn-primary") && /Créer/.test(el.textContent)), "(classes) le bouton « Créer » ne porte pas la classe primaire partagée");
  exiger(boutons.some(({ el }) => el.classList.contains("btn") && /Annuler/.test(el.textContent)), "(classes) le bouton « Annuler » ne porte pas la classe secondaire partagée");

  // (c) la confirmation partagée : refuse sans conséquence, bloque quand écartée, laisse passer validée.
  let refusee = false;
  try { await confirmWithConsequence("Supprimer", ""); } catch (e) { refusee = true; }
  exiger(refusee, "(confirmation) une confirmation SANS conséquence nommée a été posée");
  const derniereOverlay = () => document.body.children.filter((c) => c.classList.contains("modal-ov")).pop();
  const p1 = confirmWithConsequence("Supprimer le compte « x »", "ses sessions cessent immédiatement");
  const ov1 = derniereOverlay();
  exiger(ov1, "(confirmation) aucune fenêtre posée");
  const html1 = ov1 ? ov1.children[0].children[0].innerHTML : "";
  exiger(/modal-consequence/.test(html1) && /ses sessions cessent immédiatement/.test(html1) && /Supprimer le compte/.test(html1), `(confirmation) la conséquence n'est pas rendue comme telle : « ${html1.slice(0, 200)} »`);
  ov1.onclick({ target: ov1 }); // écartée (clic hors de la boîte)
  exiger((await p1) === false, "(confirmation) écartée, elle LAISSE PASSER");
  const p2 = confirmWithConsequence("Enregistrer la rétention", "purge irréversible");
  const ov2 = derniereOverlay();
  ov2.children[0].children[0].onsubmit({ preventDefault() {} }); // validée
  exiger((await p2) === true, "(confirmation) validée, elle BLOQUE");
  // `fields` : la valeur saisie revient (ressaisie du nom d'un tenant), null quand écartée.
  const p3 = confirmWithConsequence("Supprimer le tenant", "destruction", { fields: [{ name: "confirm", label: "Nom" }] });
  const ov3 = derniereOverlay(); ov3.onclick({ target: ov3 });
  exiger((await p3) === null, "(confirmation) avec champs, écartée, ne rend pas null");
}

// ---------------------------------------------------------------------------------------------
// 8. DEUX ESPACES « RECHERCHE » ET « CAS », ET DEUX FAMILLES NOMMÉES SOUS L'ONGLET PLAYBOOKS
//    (`P11.7-a`, `P11.2-c`, `P11.2-a`). Le modèle de navigation (`SPACES`, app.js) et la sidebar
//    (`index.html`) sont tenus ÉGAUX dans les deux sens : chaque espace du modèle a son lien, chaque lien
//    a son espace ; chaque section qu'un onglet mappe EXISTE dans `<main>` — une section retirée
//    d'index.html mais encore mappée (ou l'inverse) se voit ici. L'onglet des alertes vit sous « Cas »,
//    l'éditeur de requête seul sous « Recherche ». L'ancienne section de résultats n'existe plus, et un
//    import de `doSearch` serait une erreur de lien en tête de ce harnais — c'est la preuve du retrait.
//    Le libellé d'option d'action ne porte une durée que si le démon l'a SERVIE, et la suit (mutation).
// ---------------------------------------------------------------------------------------------
{
  const { SPACES } = await import(pathToFileURL(path.join(WEB, "app.js")).href);
  const html = readFileSync(path.join(WEB, "index.html"), "utf8");
  const nav = html.slice(html.indexOf('<nav class="sidebar"'), html.indexOf("</nav>"));
  const liens = [...nav.matchAll(/data-space="([a-z-]+)"[^>]*>[\s\S]*?<span>([^<]*)<\/span>/g)].map((m) => ({ space: m[1], label: m[2].trim() }));
  exiger(liens.length >= 5, `(8) instrument : ${liens.length} lien(s) d'espace lus dans la sidebar, la lecture est cassée`);
  const idsNav = new Set(liens.map((l) => l.space)), idsModele = new Set(SPACES.map((sp) => sp.id));
  exiger([...idsModele].every((id) => idsNav.has(id)) && [...idsNav].every((id) => idsModele.has(id)), `(8) espaces du modèle ≠ liens de la sidebar : modèle [${[...idsModele].join(", ")}] / sidebar [${[...idsNav].join(", ")}]`);
  // Les libellés sont lus dans le SOURCE : `&amp;` y est l'écriture d'un « & » rendu. Sans ce décodage, un
  // libellé qui en porte un ne pourrait jamais être comparé au mot que l'exploitant lit.
  const motLu = (t) => t.replace(/&amp;/g, "&").trim();
  const libelle = (id) => motLu(((liens.find((l) => l.space === id) || {}).label) || "");
  exiger(libelle("search") === "Recherche", `(8) l'espace de l'éditeur de requête ne s'appelle pas « Recherche » (« ${libelle("search")} »)`);
  // P11.7-b — l'espace du flux alerte -> cas porte les ALERTES autant que les cas ; son nom le dit. La
  // propriété générale est jugée au témoin 26 ; ici on tient l'ancrage de cet espace-là.
  exiger(/Alertes/.test(libelle("cases")) && /[Cc]as/.test(libelle("cases")), `(8) l'espace qui porte les alertes ET les cas ne nomme pas les deux (« ${libelle("cases")} »)`);
  exiger(!liens.some((l) => /Investigation|Explore/.test(l.label)), "(8) un espace porte encore le nom « Investigation » ou « Explore »");
  const espaceDe = (tab) => SPACES.find((sp) => sp.tabs.some((t) => t.id === tab));
  exiger(espaceDe("alerts") && espaceDe("alerts").id === "cases", `(8) l'onglet des alertes vit sous « ${espaceDe("alerts") && espaceDe("alerts").id} » au lieu de « cases »`);
  exiger(espaceDe("cases") && espaceDe("cases").id === "cases", "(8) l'onglet des cas ne vit pas sous l'espace Cas");
  const recherche = espaceDe("explore");
  exiger(recherche && recherche.id === "search" && recherche.tabs.length === 1 && recherche.tabs[0].sections.join(",") === "query", `(8) l'espace Recherche doit porter le seul onglet de l'éditeur, section « query » seule : ${JSON.stringify(recherche && recherche.tabs)}`);
  const sections = new Set([...html.matchAll(/<section id="([^"]+)"/g)].map((m) => m[1]));
  const manquantes = SPACES.flatMap((sp) => sp.tabs).flatMap((t) => t.sections).filter((id) => !sections.has(id));
  exiger(manquantes.length === 0, `(8) section(s) mappée(s) par un onglet mais absente(s) d'index.html : ${manquantes.join(", ")}`);
  exiger(!sections.has("search-results"), "(8) la section « résultats de recherche » (code mort mesuré) est encore dans index.html");
  // Deux familles nommées dans leurs en-têtes et leurs boutons de création ; l'interrupteur de création dit ON.
  const h2 = (id) => (html.match(new RegExp(`<h2 id="${id}">([^<]*)`)) || [])[1] || "";
  exiger(/Playbooks — règles de réponse/.test(h2("pb-h")) && /Runbooks — guides d'incident/.test(h2("rb-h")), `(8) les en-têtes ne nomment pas les deux familles : « ${h2("pb-h").trim()} » / « ${h2("rb-h").trim()} »`);
  const bouton = (id) => (html.match(new RegExp(`<button id="${id}"[^>]*>([^<]*)`)) || [])[1] || "";
  exiger(/règle de réponse/.test(bouton("pb-new")) && /guide d'incident/.test(bouton("rb-new")), `(8) les boutons de création ne nomment pas la famille : « ${bouton("pb-new")} » / « ${bouton("rb-new")} »`);
  exiger(/id="pb-enabled"[^>]*>\s*ON à l'enregistrement/.test(html), "(8) la case du formulaire playbook ne dit pas « ON à l'enregistrement »");
  exiger(!/id="rb-editor"[^>]*style=/.test(html), "(8) #rb-editor porte encore un style en ligne");
  // Libellés d'option : la durée vient du démon, et elle SUIT la valeur servie.
  const { actionKindOptionLabel } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const l4 = actionKindOptionLabel("ban_ip", 4 * 3600), l6 = actionKindOptionLabel("ban_ip", 6 * 3600), l0 = actionKindOptionLabel("ban_ip", null);
  exiger(l4.startsWith("ban_ip — ") && /\b4 h\b/.test(l4), `(8) libellé ban_ip pour une durée servie de 4 h : « ${l4} »`);
  exiger(/\b6 h\b/.test(l6) && !/\b4 h\b/.test(l6), `(8) mutation : la durée servie passe à 6 h, le libellé dit « ${l6} »`);
  exiger(!/\d/.test(l0) && /bannit/.test(l0), `(8) sans durée servie, le libellé ne doit porter AUCUN chiffre : « ${l0} »`);
  exiger(/processus/.test(actionKindOptionLabel("kill_pid")) && /service/.test(actionKindOptionLabel("stop_service")), "(8) kill_pid / stop_service ne disent pas leur effet");
  exiger(actionKindOptionLabel("format_disk") === "format_disk", "(8) une action hors vocabulaire doit rester nue, jamais recevoir une phrase rassurante");
}

// ---------------------------------------------------------------------------------------------
// 9. AUCUN BOUTON NU HORS DE L'ADMINISTRATION (`P11.4-b`, second lot) — les fabriques de bouton des modules
//    cas / producteurs (rangées de runbook, playbook, détection) rendent TOUJOURS une classe partagée, même
//    hors d'un contexte stylant ; la barre d'actions des alertes ne rend aucun bouton sans classe ; le bloc
//    MFA d'index.html ne porte plus de style en ligne ; chaque bouton d'aide `data-help` d'index.html a son
//    entrée au registre d'aide (dérivé dans les deux sens : la section Suppressions en avait une sans bouton).
//    La garde dérivée `check_every_button_wears_shared_chrome.py` juge le SOURCE ; ici, c'est le RENDU.
// ---------------------------------------------------------------------------------------------
{
  const PARTAGEES = ["btn", "btn-primary", "btn-danger", "btn-link", "picon"];
  const { caseBtn } = await import(pathToFileURL(path.join(WEB, "cases.js")).href);
  const { rowButton } = await import(pathToFileURL(path.join(WEB, "producer_ui.js")).href);
  const { rbRow } = await import(pathToFileURL(path.join(WEB, "runbooks.js")).href);
  const { alertActionBarHtml } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const porte = (el) => PARTAGEES.some((k) => el.classList.contains(k));
  for (const kind of ["ghost", "danger", "primary", undefined]) {
    const b = caseBtn("x", kind);
    exiger(porte(b) && !b.style.cssText, `(9) caseBtn('${kind}') rend un bouton sans classe partagée ou avec un style en ligne`);
  }
  exiger(caseBtn("x", "primary").classList.contains("btn-primary") && caseBtn("x", "danger").classList.contains("btn-danger"), "(9) caseBtn ne distingue pas primaire / destructif par les classes partagées");
  const r1 = rowButton("x"), r2 = rowButton("", { cls: "crud-btn", icon: "<svg/>" });
  exiger(porte(r1), "(9) rowButton sans option rend un bouton nu — hors d'un `.rulerow`, il tomberait au rendu natif");
  exiger(porte(r2) && r2.classList.contains("crud-btn"), "(9) rowButton avec `cls` perd la classe partagée ou la classe demandée");
  const ligne = rbRow({ id: 7, name: "r", managed: 1, active: true, match_kind: "*", match_key: "", steps: 2 });
  const boutons = [], parcourir = (el) => { for (const c of el.children || []) { if (c.tagName === "BUTTON") boutons.push(c); parcourir(c); } };
  parcourir(ligne);
  exiger(boutons.length >= 3, `(9) instrument : une rangée de runbook rend ${boutons.length} bouton(s), au moins 3 attendus`);
  const nus = boutons.filter((b) => !porte(b));
  exiger(nus.length === 0, `(9) ${nus.length} bouton(s) NU(s) dans une rangée de runbook : ${nus.map((b) => b.textContent || b.title).join(", ")}`);
  const barre = alertActionBarHtml({ view: "", scopeAll: false, uncased: false, mitre: "", source: "" }, { count: 3, countLabel: "3 alertes", ackableIds: [1, 2] });
  const sansClasse = [...barre.matchAll(/<button\b([^>]*)>/g)].filter((m) => !/\bclass="/.test(m[1]));
  exiger(sansClasse.length === 0, `(9) ${sansClasse.length} bouton(s) de la barre des alertes sans classe : ${sansClasse.map((m) => m[1].trim().slice(0, 40)).join(" | ")}`);
  exiger(/<button[^>]*class="btn[^"]*"[^>]*data-act="ack-all"/.test(barre), "(9) le bouton « Tout acquitter » ne porte pas la classe partagée");
  const html = readFileSync(path.join(WEB, "index.html"), "utf8");
  exiger(/<div id="mfa-block">/.test(html) && !/id="mfa-(block|status|actions|enroll)"[^>]*style=/.test(html), "(9) le bloc MFA d'index.html porte encore un style en ligne");
  exiger(/<button id="airun"[^>]*class="btn"/.test(html), "(9) le bouton de l'assistant IA (#airun) est nu");
  const clesAide = [...html.matchAll(/data-help="([a-z-]+)"/g)].map((m) => m[1]);
  exiger(clesAide.length >= 20 && clesAide.includes("suppressions"), `(9) ${clesAide.length} bouton(s) d'aide lus dans index.html ; la section Suppressions doit en porter un`);
  // Qu'une section existe pour CHAQUE déclencheur (HTML et JS) est dérivé par `check_every_help_trigger_has_a_section.py` ;
  // ce que rend l'ouvreur sur une clé sans section est le témoin 11.
}

// ---------------------------------------------------------------------------------------------
// 10. LE LEXIQUE EST APPLIQUÉ, PAS SEULEMENT ÉCRIT (`P11.8-a`). La garde de CI compte les clés du
//     dictionnaire ; elle ne dit pas si `i18nWalk` les POSE. Ici, le graphe `core.js` → `i18n.js` →
//     `system.js` est chargé une seconde fois sous `LANG='en'` (instance distincte par suffixe d'URL,
//     `localStorage.soc_lang` lu au chargement de `core.js`), le panneau Système est rendu puis parcouru
//     comme l'observateur de `app.js` le fait sur un nœud ajouté, et c'est le TEXTE qui est jugé : une
//     tuile de `system.js` et un en-tête d'`index.html` en anglais, leur infobulle aussi (y compris
//     quand le nœud ajouté PORTE lui-même l'attribut), une chaîne hors lexique laissée telle quelle, un
//     nœud texte seul traduit par son parent, et — `P11.8-d` — une valeur POSÉE PAR PROPRIÉTÉ
//     (`el.placeholder =`, `el.title =`), que le shim reflète désormais dans l'attribut comme un
//     navigateur. Témoin inverse : sous `LANG='fr'`, rien ne bouge, propriétés comprises.
//     Le shim n'a ni TreeWalker ni sélecteur d'attribut : ils sont fournis ici, au plus juste, sur
//     l'arbre qu'il enregistre (le texte d'un élément vit dans `_text`, un nœud `Text` dans `_t`).
// ---------------------------------------------------------------------------------------------
{
  Element.prototype.nodeType = 1;
  Text.prototype.nodeType = 3;
  Object.defineProperty(Text.prototype, "nodeValue", { get() { return this._t; }, set(v) { this._t = String(v); }, configurable: true });
  globalThis.NodeFilter = { SHOW_TEXT: 4 };
  const noeudsTexte = (n, acc) => {
    if (n instanceof Text) { acc.push(n); return acc; }
    if (n._text) acc.push({ get nodeValue() { return n._text; }, set nodeValue(v) { n._text = String(v); } });
    // `childNodes`, PAS `children` : un parcours de texte qui n'itère que les éléments ne rencontre
    // jamais un nœud texte. Tant que le shim confondait les deux listes, l'erreur était invisible.
    (n.childNodes || []).forEach((c) => noeudsTexte(c, acc));
    return acc;
  };
  document.createTreeWalker = (root) => { const liste = noeudsTexte(root, []); let i = -1; return { nextNode: () => liste[++i] ?? null }; };
  const attrsDe = (sel) => [...String(sel).matchAll(/\[([a-zA-Z-]+)\]/g)].map((m) => m[1]);
  const qsaOrigine = Element.prototype.querySelectorAll;
  // `matches` était ÉCRASÉ ici par une version « attribut seulement ». Depuis que le shim en porte une
  // vraie (`P11.13-g`), cet écrasement était un RECUL qui restait posé pour tout le reste de l'exécution
  // — et il aurait désarmé en silence la délégation d'événements, qui remonte par `closest`.
  Element.prototype.querySelectorAll = function (sel) {
    const as = attrsDe(sel);
    if (!as.length) return qsaOrigine.call(this, sel);
    const out = [];
    const rec = (n) => (n.children || []).forEach((c) => { if (c instanceof Element) { if (as.some((a) => a in c.attributes)) out.push(c); rec(c); } });
    rec(this);
    return out;
  };

  // Seconde instance du graphe sous `LANG='en'` : un crochet de résolution propage le suffixe d'URL aux
  // imports relatifs (`i18n.js?x` importe `./core.js` → `core.js?x`, instance neuve, `soc_lang` relu).
  const SUFFIXE = "?plume-lang=en";
  const nodeModule = await import("node:module");
  if (typeof nodeModule.registerHooks === "function") {
    nodeModule.registerHooks({ resolve(spec, ctx, next) { const r = next(spec, ctx); return ctx.parentURL && ctx.parentURL.includes(SUFFIXE) && r.url.startsWith("file:") && !r.url.includes("?") ? { ...r, url: r.url + SUFFIXE } : r; } });
  } else {
    nodeModule.register("data:text/javascript," + encodeURIComponent(
      `export async function resolve(spec, ctx, next) { const r = await next(spec, ctx); return ctx.parentURL && ctx.parentURL.includes(${JSON.stringify(SUFFIXE)}) && r.url.startsWith("file:") && !r.url.includes("?") ? { ...r, url: r.url + ${JSON.stringify(SUFFIXE)} } : r; }`));
  }
  const urlWeb = (f, suffixe = "") => pathToFileURL(path.join(WEB, f)).href + suffixe;
  localStorage.setItem("soc_lang", "en");
  const coreEN = await import(urlWeb("core.js", SUFFIXE));
  const { i18nWalk: walkEN } = await import(urlWeb("i18n.js", SUFFIXE));
  const { rendreSysteme: rendreSystemeEN } = await import(urlWeb("system.js", SUFFIXE));
  localStorage.removeItem("soc_lang");
  const coreFR = await import(urlWeb("core.js"));
  const { i18nWalk: walkFR } = await import(urlWeb("i18n.js"));
  exiger(coreEN.LANG === "en" && coreFR.LANG === "fr", `(10) instrument : les deux instances de core.js ne portent pas deux langues (« ${coreEN.LANG} » / « ${coreFR.LANG} »)`);

  // (a) une tuile de system.js rendue sous LANG='en', puis parcourue comme un nœud ajouté : anglais.
  const wrapEN = new Element("div");
  rendreSystemeEN(wrapEN, mB, hB);
  walkEN(wrapEN);
  const libellesEN = tuiles(wrapEN).map((t) => t.children.find((c) => c.classList.contains("sys-tile-l")).textContent);
  exiger(libellesEN.includes("Cumulative CPU") && libellesEN.includes("Database size"), `(10) LANG='en' : les tuiles Système ne sont pas rendues en anglais — libellés : ${libellesEN.join(" | ")}`);
  exiger(!libellesEN.includes("CPU cumulé"), "(10) LANG='en' : une tuile Système est restée en français");
  const bilanEN = wrapEN.children.find((c) => c.classList.contains("sys-bilans"));
  exiger(bilanEN && bilanEN.children.some((c) => c.textContent === "Drops on the last tick, per background loop"), "(10) LANG='en' : l'en-tête des bilans de boucles n'est pas traduit");
  // Une chaîne HORS lexique est laissée telle quelle : le dictionnaire ne traduit que ce qu'il connaît.
  const horsLexique = new Element("div"); horsLexique.textContent = "Chaîne hors lexique — témoin";
  walkEN(horsLexique);
  exiger(horsLexique.textContent === "Chaîne hors lexique — témoin", "(10) une chaîne absente du lexique a été modifiée");

  // (b) un en-tête d'index.html (texte réel du fichier) et l'infobulle de son bouton d'aide : anglais.
  const html = readFileSync(path.join(WEB, "index.html"), "utf8");
  const enTete = (html.match(/<h2 id="rules-h">([^<]*)/) || [])[1];
  const infobulle = (html.match(/<h2 id="rules-h">[^<]*<button[^>]*title="([^"]*)"/) || [])[1];
  const lienNav = (html.match(/data-space="overview"[^>]*>[\s\S]*?<span>([^<]*)<\/span>/) || [])[1];
  exiger(enTete && infobulle && lienNav, "(10) instrument : l'en-tête #rules-h, son infobulle ou le lien de navigation ne sont pas lus dans index.html");
  const h2 = new Element("h2"); h2._text = enTete;
  const bouton = new Element("button"); bouton.setAttribute("title", infobulle); h2.appendChild(bouton);
  const span = new Element("span"); span._text = lienNav;
  walkEN(h2); walkEN(span);
  exiger(h2._text.trim() === "Detection rules", `(10) LANG='en' : l'en-tête « ${enTete.trim()} » rend « ${h2._text.trim()} »`);
  exiger(bouton.getAttribute("title") === "Help: Detection rules", `(10) LANG='en' : l'infobulle d'aide rend « ${bouton.getAttribute("title")} »`);
  exiger(span._text === "Overview", `(10) LANG='en' : le lien de navigation rend « ${span._text} »`);
  // Le nœud ajouté PORTE lui-même l'attribut (bouton seul, sans parent parcouru) : traduit aussi.
  const seul = new Element("button"); seul.setAttribute("title", "Rafraîchir ce panneau");
  walkEN(seul);
  exiger(seul.getAttribute("title") === "Refresh this panel", `(10) LANG='en' : l'attribut porté par le nœud racine lui-même n'est pas traduit (« ${seul.getAttribute("title")} »)`);
  // Un nœud TEXTE seul (ce que `el.textContent = '…'` ajoute à un élément déjà attaché) : traduit par son parent.
  const statut = new Element("span"); const texteSeul = document.createTextNode("connecté"); statut.appendChild(texteSeul);
  walkEN(texteSeul);
  exiger(texteSeul.nodeValue === "connected", `(10) LANG='en' : un nœud texte passé seul à i18nWalk n'est pas traduit (« ${texteSeul.nodeValue} »)`);

  // `P11.8-i` — UN NŒUD QUI TRAVERSAIT UNE BORNE DE LITTÉRAL EST TRADUIT, UNE MOITIÉ NE L'EST PAS.
  // La garde du lexique dit que la clé EST au lexique ; seul ce banc dit que la traduction la POSE sur le
  // nœud RENDU. La distinction n'est pas théorique : le lexique a porté trois entrées qui n'étaient que des
  // MOITIÉS de nœud — nées mortes, invisibles à tous les canaux de la garde, parce que celle-ci découpait
  // sur les bornes des littéraux du code là où la traduction n'opère que sur le nœud ENTIER, une fois ébarbé.
  // La seconde exigence est la plus importante des deux : sans elle, on prouverait qu'une clé traduit, jamais
  // qu'une DEMI-clé ne traduit pas — et c'est cette seconde propriété qui rend l'entrée morte détectable.
  const pEntier = new Element("span");
  const nEntier = document.createTextNode(" (standard ouvert) pour combler les angles morts ATT&CK. Déposez un ");
  pEntier.appendChild(nEntier); walkEN(nEntier);
  exiger(nEntier.nodeValue.includes("open standard") && nEntier.nodeValue.includes("Drop a"),
    `(10) P11.8-i : le nœud RENDU de la fenêtre d'import n'est pas traduit (« ${nEntier.nodeValue} »)`);
  const pMoitie = new Element("span");
  const nMoitie = document.createTextNode(" (standard ouvert) pour combler les angles morts ATT&CK. ");
  pMoitie.appendChild(nMoitie); walkEN(nMoitie);
  exiger(nMoitie.nodeValue === " (standard ouvert) pour combler les angles morts ATT&CK. ",
    "(10) P11.8-i : une MOITIÉ de nœud est TRADUITE — le lexique porte donc une entrée qui n'est pas un nœud, et une telle entrée naît MORTE");
  // Une valeur POSÉE PAR PROPRIÉTÉ (`el.placeholder = '…'`, `el.title = '…'`) : le navigateur la reflète dans
  // l'attribut, `i18nWalk` la traduit donc comme tout autre porteur. Le geste jugé est celui des nœuds texte
  // ci-dessus — rendu sous `LANG='en'`, parcouru, puis LU — et non la seule présence de la clé au lexique :
  // une clé déclarée dont la valeur anglaise n'est jamais rendue est un faux vert.
  const parPropriete = new Element("input");
  parPropriete.placeholder = "Filtrer les termes…";
  parPropriete.title = "Rafraîchir ce panneau";
  walkEN(parPropriete);
  exiger(parPropriete.placeholder === "Filter terms…", `(10) LANG='en' : un placeholder posé par PROPRIÉTÉ rend « ${parPropriete.placeholder} » — la valeur anglaise n'est pas appliquée`);
  exiger(parPropriete.title === "Refresh this panel", `(10) LANG='en' : un title posé par PROPRIÉTÉ rend « ${parPropriete.title} »`);
  // Un texte posé SOUS UNE CLÉ (`P11.8-c`) : `Object.assign(document.createElement('div'), { textContent: … })`
  // est l'idiome par lequel une quinzaine de libellés de `web/` rejoignent le document, et le critère de
  // puits de la garde du lexique ne le lisait pas — huit d'entre eux s'affichaient en français sous
  // `LANG='en'` alors que leur module tenait un plafond de ZÉRO trou. La garde dit maintenant que la clé
  // est là ; ce témoin-ci dit que la valeur anglaise est RENDUE, ce qu'aucune garde de lexique ne peut
  // dire. C'est la même exigence que pour la valeur posée par PROPRIÉTÉ juste au-dessus.
  const sousUneCle = Object.assign(new Element("div"), { textContent: "Liens" });
  walkEN(sousUneCle);
  exiger(sousUneCle.textContent === "Links", `(10) LANG='en' : un texte posé SOUS LA CLÉ « textContent » rend « ${sousUneCle.textContent} » — la valeur anglaise n'est pas appliquée`);
  // Témoin INVERSE : sous `LANG='fr'`, le même geste ne touche à rien. Sans lui, une marche qui écrirait
  // l'anglais dans les deux langues passerait pour un succès.
  const sousUneCleFR = Object.assign(new Element("div"), { textContent: "Liens" });
  walkFR(sousUneCleFR);
  exiger(sousUneCleFR.textContent === "Liens", `(10) LANG='fr' : un texte posé SOUS LA CLÉ « textContent » a été traduit (« ${sousUneCleFR.textContent} »)`);

  // (c) témoin inverse : sous LANG='fr', la même marche ne change rien.
  const wrapFR = new Element("div");
  rendreSysteme(wrapFR, mB, hB);
  walkFR(wrapFR);
  const libellesFR = tuiles(wrapFR).map((t) => t.children.find((c) => c.classList.contains("sys-tile-l")).textContent);
  exiger(libellesFR.includes("CPU cumulé") && !libellesFR.includes("Cumulative CPU"), `(10) LANG='fr' : une tuile Système a été traduite — libellés : ${libellesFR.join(" | ")}`);
  const h2FR = new Element("h2"); h2FR._text = enTete; const boutonFR = new Element("button"); boutonFR.setAttribute("title", infobulle); h2FR.appendChild(boutonFR);
  walkFR(h2FR);
  exiger(h2FR._text === enTete && boutonFR.getAttribute("title") === infobulle, "(10) LANG='fr' : l'en-tête ou son infobulle ont été modifiés");
  const parProprieteFR = new Element("input");
  parProprieteFR.placeholder = "Filtrer les termes…"; parProprieteFR.title = "Rafraîchir ce panneau";
  walkFR(parProprieteFR);
  exiger(parProprieteFR.placeholder === "Filtrer les termes…" && parProprieteFR.title === "Rafraîchir ce panneau",
    `(10) LANG='fr' : une valeur posée par propriété a été traduite (« ${parProprieteFR.placeholder} » / « ${parProprieteFR.title} »)`);
}

// ---------------------------------------------------------------------------------------------
// 11. L'OUVREUR D'AIDE NE SE TAIT JAMAIS (`P11.4-e`). Un bouton `data-help` dont la clé n'a pas de section
//     rendait RIEN : `openHelp` retournait sans un mot (mesuré ici avant correction : zéro nœud ajouté au
//     corps du document). Témoins : la section « Jetons » s'ouvre et dit ce que le panneau fait (secret montré
//     une seule fois, révocation) ; une clé sans section ouvre un AVEU qui nomme la clé — jamais un panneau
//     vide, jamais le silence. L'existence d'une section pour chaque déclencheur est DÉRIVÉE par la garde
//     `check_every_help_trigger_has_a_section.py` ; ici, c'est le RENDU.
// ---------------------------------------------------------------------------------------------
{
  const { openHelp } = await import(pathToFileURL(path.join(WEB, "help.js")).href);
  const corps = document.body;
  const rendu = (cle) => { const avant = corps.children.length; openHelp(cle); const ajoutes = corps.children.slice(avant); return { ajoutes, texte: ajoutes.map(texte).join("\n") }; };
  const jetons = rendu("tokens");
  exiger(jetons.ajoutes.length === 1 && jetons.ajoutes[0].classList.contains("modal-ov"), `(11) openHelp('tokens') ajoute ${jetons.ajoutes.length} nœud(s) au corps : la section « Jetons » ne s'ouvre pas`);
  for (const mot of ["jetons", "une seule fois", "hec", "révoqu"]) exiger(jetons.texte.toLowerCase().includes(mot), `(11) l'aide « Jetons » ne dit pas « ${mot} »`);
  const inconnue = rendu("cle-sans-section-temoin");
  exiger(inconnue.ajoutes.length === 1, `(11) openHelp sur une clé sans section ajoute ${inconnue.ajoutes.length} nœud(s) : l'ouvreur se tait (aucun aveu)`);
  exiger(inconnue.texte.includes("cle-sans-section-temoin") && /aucune section|no help section/i.test(inconnue.texte), `(11) l'aveu sur une clé sans section ne nomme pas la clé ou ne dit pas l'absence : « ${inconnue.texte.slice(0, 120)} »`);
  exiger(!/^\s*$/.test(inconnue.texte), "(11) l'aveu est un panneau VIDE");
  console.log(`[aide] openHelp('tokens') : ${jetons.ajoutes.length} nœud(s) rendus ; clé sans section : ${inconnue.ajoutes.length} nœud(s) rendus, texte « ${inconnue.texte.replace(/\s+/g, " ").slice(0, 100)} »`);
}

// ---------------------------------------------------------------------------------------------
// 12. LE VOILE DE RECHARGEMENT NE RESTE PAS POSÉ (`P11.4-f`). `.reloading` (opacité réduite, clics coupés) est
//     posé sur le corps des alertes et de la fraîcheur avant `api()`, et retiré après. Hypothèse éprouvée ici,
//     pas supposée : existe-t-il un chemin qui le laisse ? (a) `api()` échoue ; (b) `api()` réussit et le RENDU
//     lève ; (c) deux rechargements se chevauchent (l'analyste quitte et revient pendant une requête lente).
//     L'instrument se valide lui-même : la classe DOIT être vue posée PENDANT la requête (sinon le témoin
//     « absente après » ne prouverait rien), et le rendu poison DOIT lever.
// ---------------------------------------------------------------------------------------------
{
  const { renderAlerts } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const { renderFreshness } = await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const corps = { "#alerts .body": new Element("div"), "#freshness-panel .body": new Element("div") };
  const querySelectorOrig = document.querySelector;
  document.querySelector = (sel) => corps[sel] ?? new Element("div");
  const reponse = (obj) => ({ ok: true, status: 200, text: async () => JSON.stringify(obj) });
  const cas = [
    { nom: "alertes (plate)", corps: corps["#alerts .body"], rendre: () => { S.alertGroupBy = ""; return renderAlerts(true); }, poison: { alerts: [null], total: 1 }, sain: { alerts: [], total: 0 } },
    { nom: "alertes (groupes)", corps: corps["#alerts .body"], rendre: () => { S.alertGroupBy = "rule"; return renderAlerts(true); }, poison: { groups: [null], total: 1 }, sain: { groups: [], total: 0 } },
    { nom: "fraîcheur", corps: corps["#freshness-panel .body"], rendre: () => renderFreshness(true), poison: { feeds: [null, null], pipeline_fresh: true }, sain: { feeds: [], pipeline_fresh: true } },
  ];
  const bilan = [];
  for (const c of cas) {
    // (a) api() échoue — la classe est vue posée PENDANT, absente APRÈS.
    let poseePendant = null;
    globalThis.fetch = async () => { poseePendant = c.corps.classList.contains("reloading"); throw new Error("réseau coupé (témoin)"); };
    let levee = null; try { await c.rendre(); } catch (e) { levee = e; }
    exiger(poseePendant === true, `(12) instrument : ${c.nom} — la classe .reloading n'est pas posée pendant la requête, le témoin ne prouve rien`);
    exiger(levee === null, `(12) ${c.nom} — un échec d'api() remonte jusqu'à l'appelant : ${levee && levee.message}`);
    exiger(!c.corps.classList.contains("reloading"), `(12) ${c.nom} — .reloading reste posée après un échec d'api()`);
    // (b) api() réussit, le rendu lève — la classe est déjà retirée quand le rendu commence.
    globalThis.fetch = async () => reponse(c.poison);
    levee = null; try { await c.rendre(); } catch (e) { levee = e; }
    exiger(levee !== null, `(12) instrument : ${c.nom} — le rendu poison n'a pas levé, le témoin ne prouve rien`);
    exiger(!c.corps.classList.contains("reloading"), `(12) ${c.nom} — .reloading reste posée quand le rendu lève après une requête réussie`);
    // (c) deux rechargements se chevauchent : le second (rapide) retire le voile AVANT que le premier (lent) ne
    //     rende — mesuré et nommé, ce n'est pas « reste posée » mais « retiré tôt ».
    let liberer; const lent = new Promise((r) => { liberer = r; });
    globalThis.fetch = async () => reponse(c.sain);
    const fetchSain = globalThis.fetch;
    globalThis.fetch = async () => { globalThis.fetch = fetchSain; await lent; return reponse(c.sain); };
    const premier = c.rendre();
    await new Promise((r) => setTimeout(r, 0));
    const poseeAvantSecond = c.corps.classList.contains("reloading");
    await c.rendre();
    const poseeApresSecond = c.corps.classList.contains("reloading");
    liberer(); await premier;
    exiger(poseeAvantSecond === true && poseeApresSecond === false && !c.corps.classList.contains("reloading"), `(12) ${c.nom} — chevauchement : posée avant le second ${poseeAvantSecond}, après ${poseeApresSecond}, à la fin ${c.corps.classList.contains("reloading")}`);
    bilan.push(`${c.nom} : posée pendant, retirée après échec, retirée avant un rendu qui lève, retirée par le second d'un chevauchement`);
  }
  globalThis.fetch = undefined; document.querySelector = querySelectorOrig; S.alertGroupBy = "";
  console.log(`[voile] ${bilan.join(" ; ")}`);
}

// ---------------------------------------------------------------------------------------------
// 13. CHAQUE SECTION D'AIDE REND LE MÊME TEXTE, CLÉ PAR CLÉ ET LANGUE PAR LANGUE (`P11.4-e`). Le registre
//     des sections est un CONTENU, la mécanique qui l'ouvre est un code ; les déplacer l'un hors de l'autre
//     ne doit changer aucun mot rendu. La preuve n'est pas le diff (un corps d'aide est un gabarit
//     multiligne à la colonne zéro : un déplacement qui le réindenterait en changerait le texte) : c'est
//     l'EMPREINTE du texte rendu par `openHelp(<clé>)` sous `LANG='fr'` puis sous `LANG='en'` (seconde
//     instance du graphe, témoin 10), pour CHAQUE clé du registre. Les empreintes sont imprimées : deux
//     exécutions, avant et après un déplacement, se comparent ligne à ligne. Témoins permanents : chaque clé
//     rend exactement un panneau dans chaque langue, jamais vide, et l'anglais diffère du français (une
//     section sans anglais rend le français sous `LANG='en'` : le même texte deux fois est ce trou, nommé).
// ---------------------------------------------------------------------------------------------
{
  const { createHash } = await import("node:crypto");
  const empreinte = (t) => createHash("sha256").update(t, "utf8").digest("hex").slice(0, 16);
  const SUFFIXE = "?plume-lang=en";
  const urlWeb = (f, suffixe = "") => pathToFileURL(path.join(WEB, f)).href + suffixe;
  const { openHelp: ouvrirFR } = await import(urlWeb("help.js"));
  localStorage.setItem("soc_lang", "en");
  const { openHelp: ouvrirEN } = await import(urlWeb("help.js", SUFFIXE));
  localStorage.removeItem("soc_lang");
  // Clés : celles du registre lui-même (pas des déclencheurs : une section que rien n'ouvre est rendue aussi).
  const { HELP } = await import(urlWeb("help_registry.js"));
  const cles = Object.keys(HELP).sort();
  const PLANCHER_CLES = 20;
  exiger(cles.length >= PLANCHER_CLES, `(13) instrument : ${cles.length} clé(s) de registre lues, plancher ${PLANCHER_CLES} — la dérivation est cassée`);
  // Le CONTENU d'un panneau est son titre (h3) et son corps (pre) ; le bouton de fermeture appartient à la
  // mécanique et se traduit par le lexique (témoin 14) — l'inclure rendrait « fr ≠ en » vrai même pour une
  // section sans anglais (mesuré : le témoin restait vert avec l'anglais d'une section retiré).
  const cueillir = (el, tag, acc) => { if (el.tagName === tag) acc.push(el); (el.children || []).forEach((c) => cueillir(c, tag, acc)); return acc; };
  const rendu = (ouvrir, cle) => {
    const avant = document.body.children.length; ouvrir(cle);
    const ajoutes = document.body.children.slice(avant); ajoutes.forEach((n) => n.remove());
    const contenu = ajoutes.flatMap((n) => [...cueillir(n, "H3", []), ...cueillir(n, "PRE", [])]);
    return { n: ajoutes.length, texte: contenu.map(texte).join("\n") };
  };
  const lignes = [];
  for (const cle of cles) {
    const fr = rendu(ouvrirFR, cle), en = rendu(ouvrirEN, cle);
    exiger(fr.n === 1 && en.n === 1, `(13) « ${cle} » rend ${fr.n} panneau(x) en français et ${en.n} en anglais, un seul attendu dans chaque langue`);
    exiger(fr.texte.trim() && en.texte.trim(), `(13) « ${cle} » rend un panneau VIDE (fr ${fr.texte.length} car., en ${en.texte.length} car.)`);
    exiger(!/aucune section|no help section/i.test(fr.texte + en.texte), `(13) « ${cle} » est une clé du registre et l'ouvreur rend l'aveu d'absence`);
    lignes.push(`${cle} fr=${empreinte(fr.texte)} en=${empreinte(en.texte)}${fr.texte === en.texte ? " (identiques)" : ""}`);
  }
  const identiques = lignes.filter((l) => l.endsWith("(identiques)")).map((l) => l.split(" ")[0]);
  // L'ouvreur rend le français quand une section n'a pas son anglais (`e.en ? e.en : e.fr`) : une clé
  // identique dans les deux langues est une section à laquelle il manque une langue, et elle se voit ici.
  exiger(identiques.length === 0, `(13) ${identiques.length} section(s) rendent le MÊME texte en français et en anglais : ${identiques.join(", ")}`);
  console.log(`[aide] ${cles.length} sections rendues dans les deux langues — empreintes sha256 (16 hex) du texte rendu :\n` + lignes.map((l) => `    ${l}`).join("\n"));
}

// ---------------------------------------------------------------------------------------------
// 14. LES LIBELLÉS D'INTERFACE DE L'AIDE PASSENT PAR LE LEXIQUE (`P11.8-b`). La mécanique de l'aide était
//     EXEMPTE de la garde du lexique en entier ; rien ne disait donc ce que ses boutons et titres rendaient
//     sous `LANG='en'`. Ici, chaque ouvreur de modale (section du registre, `openHelpModal`,
//     `openFreshnessHelp`, aveu sur clé sans section) est rendu sous `LANG='fr'` puis sous `LANG='en'`
//     (seconde instance du graphe, témoin 10), et le nœud ajouté est PARCOURU comme l'observateur de
//     `app.js` le fait : le bouton de fermeture doit dire « Fermer » puis « Close ». Même preuve pour le
//     guide : titres de sections, intro, nom accessible du sommaire. Instrument : la même modale sous
//     `LANG='en'` SANS la marche rend encore « Fermer » — la traduction vient du lexique appliqué, pas
//     d'un mot anglais écrit dans le module (un tel mot passerait le témoin sans lexique). Témoin
//     inverse : sous `LANG='fr'`, aucun mot anglais. Le texte d'attente du filtre du glossaire est posé
//     par propriété (`.placeholder =`) : le shim reflète maintenant cette propriété dans l'attribut comme
//     un navigateur (`P11.8-d`), donc sa valeur est jugée dans les DEUX langues ici, et non plus seulement
//     en français — une clé au lexique dont l'anglais n'est jamais rendu était un faux vert.
// ---------------------------------------------------------------------------------------------
{
  const SUFFIXE = "?plume-lang=en";
  const urlWeb = (f, suffixe = "") => pathToFileURL(path.join(WEB, f)).href + suffixe;
  const aideFR = await import(urlWeb("help.js"));
  localStorage.setItem("soc_lang", "en");
  const aideEN = await import(urlWeb("help.js", SUFFIXE));
  const { i18nWalk: walkEN } = await import(urlWeb("i18n.js", SUFFIXE));
  localStorage.removeItem("soc_lang");
  const { i18nWalk: walkFR } = await import(urlWeb("i18n.js"));
  const cueillir = (el, tag, acc) => { if (el.tagName === tag) acc.push(el); (el.children || []).forEach((c) => cueillir(c, tag, acc)); return acc; };
  // Rend une modale, la retire du corps, rend le texte de ses boutons de fermeture (après la marche si demandée).
  const fermetures = (ouvrir, marche) => {
    const avant = document.body.children.length; ouvrir();
    const ajoutes = document.body.children.slice(avant); ajoutes.forEach((n) => n.remove());
    if (marche) ajoutes.forEach(marche);
    return ajoutes.flatMap((n) => cueillir(n, "BUTTON", [])).filter((b) => b.classList.contains("m-cancel")).map(texte);
  };
  const ouvreurs = [
    ["openHelp('firewall')", () => aideFR.openHelp("firewall"), () => aideEN.openHelp("firewall")],
    ["openHelpModal", aideFR.openHelpModal, aideEN.openHelpModal],
    ["openFreshnessHelp", aideFR.openFreshnessHelp, aideEN.openFreshnessHelp],
    ["openHelp (clé sans section)", () => aideFR.openHelp("cle-sans-section-temoin"), () => aideEN.openHelp("cle-sans-section-temoin")],
  ];
  for (const [nom, fr, en] of ouvreurs) {
    const bFR = fermetures(fr), bEN = fermetures(en, walkEN);
    exiger(bFR.length === 1 && bFR[0] === "Fermer", `(14) ${nom} sous LANG='fr' : bouton de fermeture « ${bFR.join(" | ")} » au lieu de « Fermer »`);
    exiger(bEN.length === 1 && bEN[0] === "Close", `(14) ${nom} sous LANG='en' : bouton de fermeture « ${bEN.join(" | ")} » au lieu de « Close » — la clé « Fermer » manque au lexique, ou le bouton n'est pas écrit avec elle`);
  }
  const sansMarche = fermetures(aideEN.openHelpModal);
  exiger(sansMarche[0] === "Fermer", `(14) instrument : sous LANG='en' sans la marche du lexique, le bouton rend « ${sansMarche[0]} » — un mot anglais écrit dans le module passerait le témoin sans lexique`);
  // Le guide : rendu dans un hôte fourni sous `#help-body` (core.js résout `$` à l'appel), puis parcouru.
  const qsOrigine = document.querySelector;
  const guide = (rendre, marche) => {
    const hote = new Element("div");
    document.querySelector = (sel) => (sel === "#help-body" ? hote : qsOrigine(sel));
    try { rendre(); } finally { document.querySelector = qsOrigine; }
    if (marche) marche(hote);
    const toc = hote.children.find((c) => c.tagName === "NAV");
    const filtre = cueillir(hote, "INPUT", []).find((i) => i.classList.contains("hg-filter"));
    return { texte: texte(hote), sommaire: toc ? toc.getAttribute("aria-label") : null, filtre: filtre ? filtre.placeholder : null };
  };
  const gFR = guide(aideFR.renderHelpGuide, walkFR), gEN = guide(aideEN.renderHelpGuide, walkEN);
  for (const mot of ["Espaces & vues", "GXQL — Référence", "Langage de recherche. Exemples :", "Ouvrir la référence GXQL complète", "Glossaire", "Raccourcis", "Guide intégré de Plume"]) {
    exiger(gFR.texte.includes(mot), `(14) guide sous LANG='fr' : « ${mot} » absent`);
    exiger(!gEN.texte.includes(mot), `(14) guide sous LANG='en' : « ${mot} » est resté en français — la clé manque au lexique`);
  }
  for (const mot of ["Spaces & views", "GXQL — Reference", "Search language. Examples:", "Open the full GXQL reference", "Glossary", "Shortcuts", "In-app guide to Plume"]) {
    exiger(gEN.texte.includes(mot), `(14) guide sous LANG='en' : « ${mot} » absent`);
    exiger(!gFR.texte.includes(mot), `(14) guide sous LANG='fr' : un mot anglais « ${mot} » est rendu`);
  }
  exiger(gFR.sommaire === "Sommaire du guide" && gEN.sommaire === "Guide contents", `(14) nom accessible du sommaire : fr « ${gFR.sommaire} », en « ${gEN.sommaire} »`);
  // `P11.8-d` — le texte d'attente du glossaire est posé PAR PROPRIÉTÉ (`.placeholder =`). Il est désormais
  // jugé dans les DEUX langues, comme tout autre libellé du guide : le français rendu, l'anglais RENDU après
  // la marche du lexique. Tant que le shim ne reflétait pas la propriété dans l'attribut, seule la valeur
  // française était lue — la clé pouvait être au lexique et son anglais n'être jamais appliqué.
  exiger(gFR.filtre === "Filtrer les termes…", `(14) texte d'attente du filtre du glossaire sous LANG='fr' : « ${gFR.filtre} »`);
  exiger(gEN.filtre === "Filter terms…", `(14) texte d'attente du filtre du glossaire sous LANG='en' : « ${gEN.filtre} » — une valeur posée par propriété dont l'anglais n'est pas appliqué`);
  console.log(`[aide] ${ouvreurs.length} ouvreurs de modale : bouton « Fermer » sous fr, « Close » sous en après la marche du lexique ; guide : ${7 * 2} libellés rendus dans la langue de l'instance, nom accessible du sommaire traduit, et le texte d'attente du glossaire — posé par PROPRIÉTÉ — rendu dans les deux langues`);
}

// ---------------------------------------------------------------------------------------------
// 15. L'OBSERVATEUR DU LEXIQUE EST POSÉ PAR L'AMORÇAGE, ET IL TRADUIT CE QUI ARRIVE APRÈS COUP (`P11.8-a`).
//     Le témoin 10 appelle `i18nWalk` à la main ; il ne dit pas que l'amorçage POSE l'observateur, ni sur
//     quoi. Ici `app.js` est chargé sous `LANG='en'` pendant que le shim enregistre la pose : la cible est le
//     corps du document, les options couvrent les enfants, le sous-arbre et les quatre attributs affichés
//     (`title`, `placeholder`, `aria-label`, `label`) ; puis le rappel reçoit des mutations fabriquées — un
//     nœud TEXTE ajouté seul (ce que `textContent = '…'` produit sur un élément déjà attaché), un élément
//     ajouté, un attribut `title` posé après coup — et c'est le résultat qui est jugé. Témoin inverse : la
//     liaison du graphe sous `LANG='fr'` (relevée avant toute instance anglaise) n'a rien posé sur le corps.
//     L'instance `app.js?plume-lang=en` est souvent déjà chargée par les témoins 10 et 14 (les modules qui
//     importent `app.js` la tirent) ; l'import ici la garantit sans la dédoubler.
// ---------------------------------------------------------------------------------------------
{
  const SUFFIXE = "?plume-lang=en";
  const urlWeb = (f, suffixe = "") => pathToFileURL(path.join(WEB, f)).href + suffixe;
  const surLeCorps = () => observateursPoses.filter((o) => o.cible === document.body);
  exiger(observateursSurLeCorpsApresLiaison === 0, `(15) LANG='fr' : ${observateursSurLeCorpsApresLiaison} observateur(s) posé(s) sur le corps du document par la liaison — l'amorçage français n'observe rien`);
  localStorage.setItem("soc_lang", "en");
  await import(urlWeb("app.js", SUFFIXE));
  localStorage.removeItem("soc_lang");
  const poses = surLeCorps();
  exiger(poses.length === 1, `(15) LANG='en' : ${poses.length} observateur(s) posé(s) sur le corps du document, un seul attendu`);
  const pose = poses[0] || { options: {}, rappel: () => {} };
  const options = pose.options || {};
  exiger(options.childList === true && options.subtree === true && options.attributes === true, `(15) options de l'observateur : ${JSON.stringify(options)} — enfants, sous-arbre et attributs attendus`);
  exiger(JSON.stringify(options.attributeFilter) === JSON.stringify(["title", "placeholder", "aria-label", "label"]), `(15) filtre d'attributs de l'observateur : ${JSON.stringify(options.attributeFilter)}`);
  const statut = new Element("span"); const texteSeul = document.createTextNode("connecté"); statut.appendChild(texteSeul);
  const libelle = new Element("span"); libelle._text = "Rafraîchir ce dashboard";
  const bouton = new Element("button"); bouton.setAttribute("title", "Rafraîchir ce panneau");
  pose.rappel([
    { type: "childList", addedNodes: [texteSeul], target: statut },
    { type: "childList", addedNodes: [libelle], target: document.body },
    { type: "attributes", attributeName: "title", target: bouton },
  ]);
  exiger(texteSeul.nodeValue === "connected", `(15) un nœud texte ajouté seul n'est pas traduit par l'observateur (« ${texteSeul.nodeValue} »)`);
  exiger(libelle._text === "Refresh this dashboard", `(15) un élément ajouté n'est pas traduit par l'observateur (« ${libelle._text} »)`);
  exiger(bouton.getAttribute("title") === "Refresh this panel", `(15) un attribut \`title\` posé après coup n'est pas traduit par l'observateur (« ${bouton.getAttribute("title")} »)`);
  console.log(`[lexique] observateur posé par l'amorçage sous LANG='en' : corps du document, ${Object.keys(options).length} options, ${(options.attributeFilter || []).length} attributs ; nœud texte, élément et attribut posés après coup traduits`);
}

// ---------------------------------------------------------------------------------------------
// 16. LE PANNEAU D'ACCÈS DONNÉES REND SES CARTES, SA FENÊTRE ET SON PÉRIMÈTRE — ET IL DISTINGUE UN
//     REFUS D'UNE ABSENCE (`P11.14-c`). Le rendu vit dans `dataaccess.js` (extrait d'`app.js` par
//     déplacement pur) ; il est exercé ici sur le shim, sans réseau : cinq cartes titrées, un sélecteur
//     de fenêtre à trois choix avec son nom accessible, la note de périmètre et ses sept chemins.
//
//     CE QUE CE TÉMOIN A LONGTEMPS ENTÉRINÉ, ET QUI ÉTAIT LE DÉFAUT. Il exigeait que, SANS RÉSEAU,
//     chaque corps de carte dise « Aucun changement récent (…) » — c'est-à-dire qu'il exigeait du
//     panneau qu'il AFFIRME une absence de données là où aucune requête n'était partie. Le panneau
//     tenait la promesse : la même phrase sortait d'un refus du démon, d'une réponse illisible, d'une
//     panne réseau ET d'un vrai vide. C'est ce qui a produit la contradiction relevée en usage réel le
//     2026-08-25 — « toute la rétention » rendant « aucun changement récent » quand « 7 jours »
//     rendait des lignes, un sur-ensemble affichant moins que son sous-ensemble. Mesuré le même jour :
//     le SQL de la fenêtre large est celui de la fenêtre étroite MOINS son conjoint `ts >= …`, et il
//     rend toujours au moins autant de lignes ; ce que la fenêtre large rend de différent, c'est un
//     REFUS du démon, NOMMÉ PAR SON SITE et non cité (`P11.21-a`) : en 422 celui que forme
//     `TruncatedAggregate::message` (`daemon/src/cold_store/exactness.rs`) et que rend
//     `refuse_truncated_aggregate` (`daemon/src/handlers/query.rs`) ; en 400 celui que forme
//     `run_query_ex` (`daemon/src/query_exec.rs`) et que rend `bad_req` (`daemon/src/main.rs`). La
//     contradiction naissait donc à l'AFFICHAGE, et ce témoin la protégeait.
//
//     LES TROIS ISSUES SONT DÉSORMAIS TENUES, DANS LES DEUX SENS. Un refus doit NOMMER sa cause et ne
//     doit accuser NI la collecte NI l'absence de données ; un VRAI vide doit rester une absence (sans
//     quoi un correctif dégénéré — « avoue toujours » — passerait le premier témoin sans rien prouver) ;
//     des lignes doivent rendre une table. La distinction est jugée sur la STRUCTURE (trois classes,
//     trois textes, tous distincts), pas sur une phrase recopiée : une reformulation ne casse pas le
//     témoin, mais un aplatissement des trois issues sur une seule, si.
// ---------------------------------------------------------------------------------------------
{
  const { renderDataAccess, daRenduDeReponse } = await import(pathToFileURL(path.join(WEB, "dataaccess.js")).href);
  const hote = new Element("div");
  const qsOrigine = document.querySelector;
  document.querySelector = (sel) => (sel === "#da-body" ? hote : qsOrigine(sel));
  try { await renderDataAccess(); await new Promise((r) => setTimeout(r, 0)); } finally { document.querySelector = qsOrigine; }
  const h2De = (el) => { const h = el.children.find((x) => x.tagName === "H2"); return h ? h.textContent : null; };
  const cartes = hote.children.filter((c) => c.tagName === "SECTION" && c.dataset.da);
  exiger(cartes.length === 5, `(16) ${cartes.length} carte(s) d'accès données rendue(s), cinq attendues`);
  const titres = cartes.map(h2De);
  for (const t of ["Qui touche quoi (accès données)", "Intégrité (FIM)", "RBAC Kubernetes (kube-rbac)"]) exiger(titres.includes(t), `(16) carte « ${t} » absente — titres : ${titres.join(" | ")}`);
  const corpsEl = cartes.map((c) => c.children.find((x) => x.classList.contains("body")));
  const corps = corpsEl.map((b) => (b ? b.textContent : "(pas de corps)"));
  // SANS RÉSEAU, RIEN N'EST ÉTABLI. Le placeholder « ... » doit avoir été remplacé (le panneau conclut),
  // et ce qu'il rend est un aveu qui NOMME la cause — jamais une absence de données.
  exiger(corps.every((t) => t && t !== "..." && !t.endsWith("...")), `(16) sans réseau, un corps de carte reste au placeholder : ${corps.join(" | ")}`);
  const avecCause = corpsEl.map((b) => (b && b.children.find((x) => x.classList.contains("bad"))) || null);
  exiger(avecCause.every(Boolean), `(16) sans réseau, un corps de carte ne rend pas un aveu de cause : ${corps.join(" | ")}`);
  // TROIS ISSUES DISTINCTES, sur la MÊME fonction pure et la MÊME fenêtre. Aucune phrase n'est recopiée :
  // c'est la CARDINALITÉ (trois classes, trois textes) qui est exigée, plus la présence de la cause
  // servie par le démon dans le seul rendu qui a le droit de la porter.
  const SOQL = "search source=dataaccess | stats count by path,user | sort -count | head 30";
  // `P11.21-a` — LA CAUSE INJECTÉE EST FABRIQUÉE ICI, ET ELLE LE DIT. Elle citait mot pour mot le refus
  // 422 du démon ; MESURÉ le 2026-08-29, cette citation avait DÉRIVÉ — le démon sert « un RÉSULTAT FAUX »
  // (`TruncatedAggregate::message`, `daemon/src/cold_store/exactness.rs`) là où ce banc écrivait « un
  // NOMBRE FAUX » — et elle avait vieilli EN SILENCE, puisque rien ne l'y adossait : le rendu jugé ici
  // n'est PAS couplé au texte, il rend le champ `error` quelle qu'en soit la forme. Une chaîne
  // visiblement FABRIQUÉE prouve donc la propriété mieux qu'une citation réaliste, et elle ne peut plus
  // périmer. La console a reçu le même remède un fichier plus loin (`web/dataaccess.js`) : nommer le
  // SITE, ne jamais recopier la phrase.
  const CAUSE = "CAUSE-DE-REFUS-FABRIQUÉE-PAR-CE-BANC : aucune phrase du démon n'est citée ici";
  const refus = daRenduDeReponse({ error: CAUSE }, "all", SOQL);
  const vide = daRenduDeReponse({ columns: ["path"], rows: [] }, "all", SOQL);
  const lignes = daRenduDeReponse({ columns: ["path", "count"], rows: [["/etc/shadow", 3]] }, "all", SOQL);
  const issues = [refus, vide, lignes];
  exiger(new Set(issues.map((e) => e.className)).size === 3, `(16) les trois issues d'une réponse partagent une classe : ${issues.map((e) => e.className).join(" | ")}`);
  exiger(new Set(issues.map((e) => e.textContent)).size === 3, `(16) les trois issues d'une réponse rendent le même texte : ${issues.map((e) => e.textContent).join(" | ")}`);
  exiger(refus.textContent.includes(CAUSE), `(16) le refus du démon n'est pas rendu à l'analyste — la cause et les voies exactes qu'il nomme sont perdues : « ${refus.textContent} »`);
  exiger(!/capteur/i.test(refus.textContent), `(16) un refus accuse la collecte : « ${refus.textContent} »`);
  exiger(!vide.textContent.includes(CAUSE) && vide.textContent.includes("Aucun"), `(16) un VRAI vide ne se dit plus comme une absence — un correctif qui avouerait TOUJOURS passerait le témoin du refus sans rien prouver : « ${vide.textContent} »`);
  exiger(lignes.children.some((c) => c.tagName === "TABLE"), `(16) des lignes ne rendent pas de table : « ${lignes.textContent} »`);
  // La fenêtre ÉTROITE ne conclut pas comme la large : sur toute la rétention un vide porte sur la
  // collecte, sur sept jours il porte sur la fenêtre. Deux textes, une seule fonction.
  const vide7j = daRenduDeReponse({ columns: ["path"], rows: [] }, "7d", SOQL);
  exiger(vide7j.textContent !== vide.textContent, `(16) le vide d'une fenêtre étroite et celui de toute la rétention disent la même chose : « ${vide.textContent} »`);
  const barre = hote.children.find((c) => c.classList.contains("da-winbar"));
  const selecteur = barre && barre.children.find((c) => c.tagName === "SELECT");
  exiger(!!selecteur && selecteur.children.length === 3 && selecteur.getAttribute("aria-label") === "Fenêtre d'analyse (DLP)", `(16) sélecteur de fenêtre : ${selecteur ? selecteur.children.length + " option(s), nom « " + selecteur.getAttribute("aria-label") + " »" : "absent"}`);
  exiger(!!barre && barre.children.some((c) => c.tagName === "SPAN" && c.textContent.startsWith("Fenêtre : toute la rétention")), "(16) le libellé de fenêtre n'annonce pas « toute la rétention »");
  const note = hote.children.find((c) => c.classList.contains("da-note"));
  exiger(!!note && h2De(note) === "Périmètre surveillé (hôte)", `(16) note de périmètre : ${note ? "titre « " + h2De(note) + " »" : "absente"}`);
  const puces = note ? note.children.flatMap((c) => c.children || []).filter((c) => c.classList.contains("plugchip")) : [];
  exiger(puces.length === 7 && puces.some((c) => c.textContent === "/etc/shadow"), `(16) ${puces.length} chemin(s) surveillé(s) rendu(s), sept attendus`);
  console.log(`[accès données] ${cartes.length} cartes ; sans réseau, ${avecCause.filter(Boolean).length} corps avouent leur cause au lieu d'affirmer une absence ; trois issues distinctes (refus « ${refus.className} », vide « ${vide.className} », lignes « ${lignes.className} ») sur la même fonction, et le vide de sept jours ne conclut pas comme celui de toute la rétention ; sélecteur à ${selecteur ? selecteur.children.length : 0} choix, ${puces.length} chemins surveillés`);
}

// ---------------------------------------------------------------------------------------------
// 17. LES LOOKUPS RENDENT LEUR LIGNE ET LISENT LEUR CSV. Le bloc vit dans `lookups.js` (extrait d'`app.js` par
//     déplacement pur) ; ses deux fonctions pures sont exercées sur le shim : la ligne d'un lookup porte son
//     nom, son badge d'origine, sa clé, ses colonnes de sortie et un bouton de suppression habillé ; le
//     collage CSV lit les guillemets (virgule interne, guillemet doublé) et refuse un collage sans données
//     avec un message. Sans réseau, la liste ne lève pas et ne rend rien (le 403 d'un rôle sans droit suit
//     le même chemin).
// ---------------------------------------------------------------------------------------------
{
  const { lookupRow, parseCsvRows, loadLookups } = await import(pathToFileURL(path.join(WEB, "lookups.js")).href);
  const ligne = lookupRow({ name: "geoip", key_field: "ip", cols: "country,asn", rows: 3, updated: 0, managed: 0 });
  const enfants = (tag) => ligne.children.filter((c) => c.tagName === tag);
  const nom = enfants("SPAN").find((c) => c.classList.contains("rulename"));
  exiger(!!nom && nom.textContent.startsWith("geoip") && nom.children.some((c) => c.classList.contains("mgbadge")), `(17) la ligne ne porte pas le nom et le badge d'origine : « ${nom ? nom.textContent : "(sans nom)"} »`);
  const cle = enfants("CODE")[0];
  exiger(!!cle && cle.textContent === "clé=ip", `(17) la clé rend « ${cle ? cle.textContent : "(absente)"} »`);
  const meta = enfants("SPAN").find((c) => c.classList.contains("rulemeta"));
  exiger(!!meta && meta.textContent === "3 ligne(s) - country, asn" && meta.title.startsWith("colonnes de sortie"), `(17) les colonnes de sortie rendent « ${meta ? meta.textContent : "(absentes)"} »`);
  const suppr = enfants("BUTTON")[0];
  exiger(!!suppr && suppr.classList.contains("crud-btn") && suppr.title === "Supprimer", `(17) le bouton de suppression : ${suppr ? "classe « " + suppr.className + " », titre « " + suppr.title + " »" : "absent"}`);
  const sansColonne = lookupRow({ name: "asn", key_field: "ip", cols: "", rows: 0 });
  exiger(sansColonne.children.some((c) => c.textContent === "0 ligne(s) - aucune colonne de sortie"), "(17) un lookup sans colonne de sortie ne le dit pas");
  const lu = parseCsvRows('ip,label\n"1.2.3.4","a, b"\n5.6.7.8,"dit ""x"""\n');
  exiger(JSON.stringify(lu) === JSON.stringify([{ ip: "1.2.3.4", label: "a, b" }, { ip: "5.6.7.8", label: 'dit "x"' }]), `(17) lecture CSV : ${JSON.stringify(lu)}`);
  let refus = null; try { parseCsvRows("ip,label\n"); } catch (e) { refus = e.message; }
  exiger(typeof refus === "string" && refus.startsWith("CSV : une ligne d'en-têtes"), `(17) un CSV sans données est accepté ou refusé sans message : ${refus}`);
  const hote = new Element("div");
  const qsOrigine = document.querySelector;
  document.querySelector = (sel) => (sel === "#lookup-list" ? hote : qsOrigine(sel));
  let leve = null; try { await loadLookups(); } catch (e) { leve = e; } finally { document.querySelector = qsOrigine; }
  exiger(leve === null && hote.children.length === 0, `(17) sans réseau, la liste ${leve ? "lève « " + leve.message + " »" : "rend " + hote.children.length + " nœud(s)"}`);
  console.log(`[lookups] ligne rendue (nom, badge, clé, ${2} colonnes, bouton habillé), CSV lu (${lu.length} lignes, guillemets), refus nommé sans données, liste silencieuse sans réseau`);
}

// ---------------------------------------------------------------------------------------------
// 18. UNE TUILE DE DASHBOARD REND SON EN-TÊTE, SES OUTILS SELON LE DROIT, ET AVOUE L'ERREUR DE SA GRILLE.
//     Le rendu vit dans `dashboards.js` (extrait d'`app.js` par déplacement pur) ; il est exercé ici sur le shim,
//     sans réseau : le titre et le compte de panneaux avec la mention « privé » ; la largeur en colonnes
//     reportée sur la tuile et le sélecteur ; les outils d'un éditeur (favori, rafraîchir, ajouter, PDF,
//     instantané, renommer, largeur, supprimer — chacun avec son infobulle, aucun bouton nu) contre ceux d'un
//     lecteur (quatre, sans coin de redimensionnement) ; une grille dont la liste de panneaux ne peut pas
//     être lue rend « erreur : … », jamais le placeholder ; une tuile repliée ne demande rien.
// ---------------------------------------------------------------------------------------------
{
  const { renderDashboard } = await import(pathToFileURL(path.join(WEB, "dashboards.js")).href);
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const tuile = renderDashboard({ id: 7, name: "Posture", panels: 2, cols: 3, visibility: "private", collapsed: false, editable: true });
  await tick();
  // `P11.13-g` — CE TÉMOIN EXIGEAIT `=== 7`, UN NOMBRE, et il passait parce que `dataset` était un objet nu.
  // Un `dataset` réel écrit et relit un ATTRIBUT : sa valeur est TOUJOURS une chaîne. L'exigence d'avant
  // n'était donc vraie que dans le simulacre — et une comparaison numérique à un `dataset` serait fausse
  // dans un navigateur. La valeur est relue par les DEUX chemins pour que le reflet lui-même soit tenu.
  exiger(tuile.tagName === "SECTION" && tuile.classList.contains("dashtile") && tuile.dataset.id === "7" && tuile.getAttribute("data-id") === "7", `(18) la tuile : ${tuile.tagName} « ${tuile.className} » id=${JSON.stringify(tuile.dataset.id)} / attribut ${JSON.stringify(tuile.getAttribute("data-id"))}`);
  exiger(tuile.style.flexBasis === "calc(75% - 12px)", `(18) largeur de trois colonnes non reportée : « ${tuile.style.flexBasis} »`);
  const h3 = cueillir(tuile, (e) => e.tagName === "H3", [])[0];
  exiger(!!h3 && h3.textContent === "Posture", `(18) titre « ${h3 ? h3.textContent : "(absent)"} »`);
  const meta = cueillir(tuile, (e) => e.classList.contains("dashmeta"), [])[0];
  exiger(!!meta && meta.textContent === "2 panneau(x) - prive", `(18) compte de panneaux « ${meta ? meta.textContent : "(absent)"} »`);
  const outils = cueillir(tuile, (e) => e.classList.contains("paneltools"), [])[0];
  const boutons = outils ? outils.children.filter((e) => e.tagName === "BUTTON") : [];
  const titres = boutons.map((b) => b.title);
  for (const t of ["Ajouter aux favoris", "Rafraîchir ce dashboard", "Ajouter un panneau", "Imprimer / exporter ce dashboard en PDF", "Renommer le dashboard", "Supprimer le dashboard"]) exiger(titres.includes(t), `(18) outil « ${t} » absent — ${titres.join(" | ")}`);
  exiger(boutons.every((b) => b.type === "button" && b.classList.contains("picon") && b.title), `(18) un outil est nu (sans type, classe ou infobulle) : ${boutons.map((b) => b.type + "/" + b.className + "/" + b.title).join(" | ")}`);
  const largeur = outils ? outils.children.find((e) => e.tagName === "SELECT") : null;
  exiger(!!largeur && largeur.children.length === 4 && largeur.value === "3", `(18) sélecteur de largeur : ${largeur ? largeur.children.length + " options, valeur « " + largeur.value + " »" : "absent"}`);
  const grille = cueillir(tuile, (e) => e.classList.contains("dashgrid"), [])[0];
  exiger(!!grille && grille.children.length === 1 && grille.children[0].classList.contains("bad") && grille.children[0].textContent.startsWith("erreur : "), `(18) sans réseau, la grille rend « ${grille ? grille.textContent : "(absente)"} » au lieu d'avouer l'erreur`);
  exiger(tuile.children.some((e) => e.classList.contains("dcorner")), "(18) l'éditeur n'a pas de coin de redimensionnement");
  const lecteur = renderDashboard({ id: 8, name: "Lecture", panels: 0, cols: 1, editable: false });
  await tick();
  const outilsL = cueillir(lecteur, (e) => e.classList.contains("paneltools"), [])[0];
  exiger(!!outilsL && outilsL.children.length === 4 && !outilsL.children.some((e) => e.classList.contains("editonly")), `(18) un lecteur voit ${outilsL ? outilsL.children.length : 0} outil(s), quatre attendus sans outil d'édition`);
  exiger(!lecteur.children.some((e) => e.classList.contains("dcorner")) && lecteur.style.flexBasis === "calc(25% - 12px)", "(18) un lecteur a un coin de redimensionnement, ou une colonne n'est pas reportée");
  const repliee = renderDashboard({ id: 9, name: "Repliée", panels: 1, cols: 2, collapsed: true });
  await tick();
  const grilleR = cueillir(repliee, (e) => e.classList.contains("dashgrid"), [])[0];
  exiger(repliee.classList.contains("collapsed") && !!grilleR && grilleR.textContent === "..." && typeof grilleR._deferredLoad === "function", `(18) une tuile repliée a demandé sa grille : « ${grilleR ? grilleR.textContent : "(absente)"} »`);
  console.log(`[dashboards] tuile d'éditeur : ${boutons.length} outils habillés, largeur ${largeur ? largeur.value : "?"} col, grille qui avoue l'erreur ; lecteur : ${outilsL ? outilsL.children.length : 0} outils ; repliée : différée`);
}

// ---------------------------------------------------------------------------------------------
// 19. L'IDENTITÉ EST DITE, ET L'ÉCRAN DE CONNEXION VERROUILLE CE QU'IL COUVRE. Le bloc vit dans `login.js`
//     (extrait d'`app.js` par déplacement pur). Sur le shim : l'encart d'identité nomme l'utilisateur, son
//     rôle et sa MÉTHODE quand elle n'est pas la session cookie (une session SSO ou démo doit se voir), il se
//     cache quand personne n'est authentifié ; l'overlay de connexion pose `login-locked` sur le corps du
//     document ET coupe la boucle d'auto-rafraîchissement (sinon l'API est martelée en 401 derrière l'écran),
//     et la retire en repartant.
// ---------------------------------------------------------------------------------------------
{
  const { setAuthUI, showLogin } = await import(pathToFileURL(path.join(WEB, "login.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const encart = new Element("div"), identite = new Element("span"), overlay = new Element("div");
  const qsOrigine = document.querySelector;
  document.querySelector = (sel) => ({ "#authbox": encart, "#auth-id": identite, "#login-ov": overlay }[sel] || qsOrigine(sel));
  try {
    S.AUTH = { user: "alice", role: "admin", auth_method: "sso" };
    setAuthUI();
    exiger(identite.textContent === "alice · admin (sso)", `(19) l'encart d'identité rend « ${identite.textContent} »`);
    exiger(identite.title === "Connecté : alice (admin) — sso", `(19) l'infobulle d'identité rend « ${identite.title} »`);
    exiger(encart.hidden === false, "(19) l'encart d'identité reste caché alors qu'une session est ouverte");
    S.AUTH = { user: "bob", role: "viewer", auth_method: "cookie" };
    setAuthUI();
    exiger(identite.textContent === "bob · viewer", `(19) la session cookie ne doit pas nommer sa méthode : « ${identite.textContent} »`);
    S.AUTH = null;
    setAuthUI();
    exiger(encart.hidden === true, "(19) l'encart d'identité reste visible sans session");
    S.autoTimer = setInterval(() => {}, 1e6);
    showLogin(true);
    exiger(overlay.hidden === false && document.body.classList.contains("login-locked"), `(19) l'écran de connexion : overlay ${overlay.hidden ? "caché" : "visible"}, corps ${document.body.classList.contains("login-locked") ? "verrouillé" : "NON verrouillé"}`);
    exiger(S.autoTimer === null, "(19) la boucle d'auto-rafraîchissement tourne encore derrière l'écran de connexion : l'API serait martelée en 401");
    showLogin(false);
    exiger(overlay.hidden === true && !document.body.classList.contains("login-locked"), "(19) le verrou du corps du document survit à la fermeture de l'écran de connexion");
  } finally { document.querySelector = qsOrigine; S.AUTH = null; }
  console.log(`[connexion] identité nommée avec sa méthode hors session cookie, encart caché sans session, écran de connexion qui verrouille le corps et coupe l'auto-rafraîchissement`);
}

// ---------------------------------------------------------------------------------------------
// 20. UN ONGLET INTERDIT, INCONNU OU RENOMMÉ NE MÈNE NULLE PART D'AUTRE QUE LA VUE D'ENSEMBLE. Le modèle
//     `SPACES` est jugé par le témoin 8 ; ici c'est la RÉSOLUTION, extraite d'`app.js` vers `navigation.js` :
//     un hash historique suit son alias, un onglet réservé à l'administration est refusé au non-admin (le
//     repli est le même que pour un hash inventé — l'interface ne s'ouvre pas sur une section qu'un rôle
//     n'a pas le droit de voir), un onglet d'un mode non actif est refusé, et `location.hash` n'est JAMAIS
//     réécrit (le lien profond survit au repli).
// ---------------------------------------------------------------------------------------------
{
  const { currentTab, currentViewName } = await import(pathToFileURL(path.join(WEB, "navigation.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const resolu = (hash) => { location.hash = hash; const t = currentTab(); return { onglet: t, hash: location.hash }; };
  S.isAdmin = false; S.AUTH = null; S.MY_TENANTS = null;
  exiger(resolu("#cases").onglet === "cases", `(20) un onglet ouvert à tous ne se résout pas : « ${resolu("#cases").onglet} »`);
  exiger(resolu("#query").onglet === "explore", `(20) l'alias historique « query » ne mène pas à l'éditeur de requête : « ${resolu("#query").onglet} »`);
  exiger(resolu("#notifications").onglet === "alerts", `(20) l'alias historique « notifications » ne mène pas aux alertes : « ${resolu("#notifications").onglet} »`);
  exiger(resolu("#onglet-invente").onglet === "overview", `(20) un hash inconnu mène à « ${resolu("#onglet-invente").onglet} » au lieu de la vue d'ensemble`);
  exiger(resolu("#users").onglet === "overview", `(20) un onglet d'administration est servi à un non-admin : « ${resolu("#users").onglet} »`);
  exiger(resolu("#tenants").onglet === "overview", `(20) l'onglet des tenants est servi hors mode multi-tenant : « ${resolu("#tenants").onglet} »`);
  exiger(resolu("#users").hash === "#users", `(20) la résolution a RÉÉCRIT location.hash en « ${resolu("#users").hash} » : le lien profond est perdu`);
  S.isAdmin = true;
  exiger(currentTab() === "users", `(20) un admin n'atteint pas l'onglet d'administration : « ${currentTab()} »`);
  exiger(currentViewName() === currentTab(), "(20) l'alias historique de la vue courante ne suit plus l'onglet courant");
  S.isAdmin = false; location.hash = "";
  console.log(`[navigation] résolution : deux alias historiques suivis, hash inconnu et onglet d'administration repliés sur la vue d'ensemble sans réécrire le lien profond, onglet admin atteint par un admin`);
}

// ---------------------------------------------------------------------------------------------
// 21. UN CAS S'OUVRE ET SE REFERME PAR LE MÊME GESTE, ET UN ÉTAT TERNE DIT POURQUOI IL L'EST (`P11.11-a`).
//     Ce qui MANQUAIT et ce qui était SEULEMENT INATTEIGNABLE ne se corrigent pas pareil, donc le témoin
//     sépare les deux. (a) Le geste de fermeture EXISTAIT — un bouton-icône « Fermer le détail » dans
//     l'en-tête du détail : ce témoin-là est vert avant comme après, et c'est lui qui interdit de raconter
//     que la console n'avait aucune fermeture. (b) Ce qui manquait, c'est que la LIGNE qui ouvre referme :
//     elle passe désormais par le dépli partagé (`disclosure`, témoin 7), donc elle porte `aria-expanded`,
//     `aria-controls`, n'est jamais grisée, et un second clic rend le document à son état de départ.
//     (c) Les deux fermetures sont le MÊME chemin : refermer par le bouton du détail repeint la ligne, sans
//     quoi la liste continuerait d'affirmer que le cas est déplié. (d) Un cas terminé rendait son sélecteur
//     de statut ABSENT, sans un mot ; il est maintenant PRÉSENT, inerte, avec sa raison en clair — et le
//     témoin inverse (un cas en cours) interdit qu'une version qui dirait TOUJOURS « inerte » passe.
//     (e) Un droit qui manque et un état qui ne bouge plus se disent DIFFÉREMMENT.
// ---------------------------------------------------------------------------------------------
{
  const { caseRow, renderCaseDetail } = await import(pathToFileURL(path.join(WEB, "cases.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };

  const encours = { id: 7, title: "Balayage", status: "in_progress", severity: 3, priority: 2, items: 0, ts: 1000, updated: 1000 };
  const clos = { id: 9, title: "Ancien", status: "closed", severity: 1, priority: 4, items: 0, ts: 900, updated: 950, closed_ts: 960 };
  const reponse = (o) => ({ ok: true, status: 200, text: async () => JSON.stringify(o) });
  const fetchOrigine = globalThis.fetch, qsOrigine = document.querySelector;
  const detail = new Element("div"); detail.id = "case-detail";
  const liste = new Element("div"); liste.id = "cases-list";
  let lignes = [];
  liste.querySelector = () => lignes[0] ?? null;
  liste.querySelectorAll = () => lignes;
  document.querySelector = (sel) => (sel === "#case-detail" ? detail : sel === "#cases-list" ? liste : new Element("div"));
  globalThis.fetch = async (url) => {
    if (/\/cases\/\d+\/links$/.test(url)) return reponse({ links: [] });
    if (/\/cases\/\d+\/runbooks$/.test(url)) return reponse({ incident_tier: null, available: [] });
    if (/\/cases\/\d+\/steps$/.test(url)) return reponse({ steps: [], progress: { total: 0, done: 0, skipped: 0 }, runbook: null });
    return reponse(/\/cases\/9$/.test(url) ? clos : encours);
  };
  try {
    S.AUTH = { user: "eve", role: "editor" }; S.caseSelectedId = null;

    // (a) LE GESTE DE FERMETURE EXISTAIT DÉJÀ — présent, mais loin de la ligne qui a ouvert.
    const hote = new Element("div");
    renderCaseDetail(hote, encours); await tick();
    const fermer = cueillir(hote, (e) => e.tagName === "BUTTON" && e.title === "Fermer le détail", [])[0];
    exiger(!!fermer && fermer.classList.contains("picon"), "(21) le détail d'un cas ne rend aucun bouton de fermeture habillé — le défaut ne serait plus « inatteignable » mais « absent »");

    // (b) LA LIGNE OUVRE ET REFERME. État de départ relevé AVANT, comparé APRÈS l'aller-retour.
    const ligne = caseRow(encours); lignes = [ligne];
    const depart = { enfants: detail.children.length, deplie: ligne.getAttribute("aria-expanded"), on: ligne.classList.contains("on"), selection: S.caseSelectedId };
    exiger(depart.deplie === "false" && !depart.on, `(21) au rendu, la ligne ne porte pas son état replié : aria-expanded=« ${depart.deplie} », .on=${depart.on}`);
    exiger(ligne.getAttribute("aria-controls") === "case-detail", `(21) la ligne ne déclare pas le panneau qu'elle pilote : aria-controls=« ${ligne.getAttribute("aria-controls")} »`);
    ligne.onclick(); await tick();
    exiger(S.caseSelectedId === 7 && detail.children.length === 1, `(21) le premier clic n'ouvre pas le cas (sélection ${S.caseSelectedId}, ${detail.children.length} enfant(s))`);
    exiger(ligne.getAttribute("aria-expanded") === "true" && ligne.classList.contains("on"), "(21) le cas ouvert ne se lit pas sur la ligne qui l'a ouvert");
    exiger(ligne.disabled !== true, "(21) la ligne est grisée pendant que le cas est ouvert");
    ligne.onclick(); await tick();
    exiger(S.caseSelectedId === depart.selection && detail.children.length === depart.enfants, `(21) le second clic ne REFERME pas le cas (sélection ${S.caseSelectedId}, ${detail.children.length} enfant(s)) — c'est le constat de \`P11.11-a\``);
    exiger(ligne.getAttribute("aria-expanded") === depart.deplie && ligne.classList.contains("on") === depart.on, "(21) après l'aller-retour, la ligne ne revient pas à son état de départ");

    // (c) LES DEUX FERMETURES SONT LE MÊME CHEMIN : celle du détail repeint la ligne.
    ligne.onclick(); await tick();
    exiger(ligne.getAttribute("aria-expanded") === "true", "(21) instrument : la réouverture a échoué, la suite ne prouve rien");
    const fermerDetail = cueillir(detail, (e) => e.tagName === "BUTTON" && e.title === "Fermer le détail", [])[0];
    exiger(!!fermerDetail, "(21) instrument : le détail ouvert ne porte pas son bouton de fermeture");
    fermerDetail.onclick(); await tick();
    exiger(detail.children.length === 0 && S.caseSelectedId === null, "(21) le bouton du détail ne referme pas le cas");
    exiger(ligne.getAttribute("aria-expanded") === "false" && !ligne.classList.contains("on"), "(21) refermé par le détail, la LIGNE affirme encore que le cas est déplié — les deux fermetures ne sont pas le même chemin");

    // (d) UN CAS TERMINÉ : contrôle PRÉSENT, inerte, raison en clair. Témoin inverse sur un cas en cours.
    const statut = (c) => { const h = new Element("div"); renderCaseDetail(h, c); return cueillir(h, (e) => e.tagName === "LABEL" && /^Statut/.test(e.textContent), [])[0]; };
    const labClos = statut(clos), labEnCours = statut(encours);
    exiger(!!labClos, "(21) un cas terminé ne rend AUCUN contrôle de statut : l'inertie reste indevinable (le défaut d'origine)");
    const selClos = labClos && labClos.children.find((e) => e.tagName === "SELECT");
    exiger(selClos && selClos.disabled === true, "(21) le contrôle de statut d'un cas terminé n'est pas rendu inerte");
    exiger(labClos && /Inerte par nature/.test(labClos.textContent) && /Rouvrir/.test(labClos.textContent), `(21) le contrôle inerte ne porte pas sa raison ni la sortie : « ${labClos && labClos.textContent} »`);
    const selEnCours = labEnCours && labEnCours.children.find((e) => e.tagName === "SELECT");
    exiger(!!selEnCours && selEnCours.disabled !== true, "(21) témoin inverse : le statut d'un cas EN COURS est inerte lui aussi — une version qui grise tout passerait le témoin précédent");
    exiger(labEnCours && !/Inerte par nature/.test(labEnCours.textContent), `(21) témoin inverse : un cas en cours se dit inerte — « ${labEnCours && labEnCours.textContent} »`);
    // le cadre d'état lui-même tranche entre les deux lectures, et la ligne terne dit pourquoi elle l'est.
    const cadre = (c) => cueillir(caseRow(c), (e) => e.classList.contains("casest"), [])[0];
    const cClos = cadre(clos), cEnCours = cadre(encours);
    exiger(cClos && /terminé/.test(cClos.title || ""), `(21) le cadre d'état d'un cas terminé ne dit pas qu'il est terminé : « ${cClos && cClos.title} »`);
    exiger(cEnCours && cEnCours.title && cEnCours.title !== cClos.title, `(21) le cadre d'état d'un cas en cours dit la même chose qu'un cas terminé : « ${cEnCours && cEnCours.title} »`);
    exiger(/estompée/.test(caseRow(clos).title || ""), "(21) la ligne estompée d'un cas terminé ne dit pas qu'elle reste active");

    // (e) UN DROIT QUI MANQUE SE DIT AUTREMENT QU'UN ÉTAT QUI NE BOUGE PLUS.
    S.AUTH = { user: "bob", role: "viewer" };
    const hLecteur = new Element("div"); renderCaseDetail(hLecteur, clos); await tick();
    const texteLecteur = hLecteur.textContent;
    exiger(/Lecture seule/.test(texteLecteur) && /rôle éditeur/.test(texteLecteur), `(21) un lecteur ne voit AUCUNE action et rien ne lui dit que c'est un droit qui manque : « ${texteLecteur.slice(0, 200)} »`);
    exiger(!/Inerte par nature/.test(texteLecteur), "(21) le droit manquant est rendu avec les mots de l'inertie par nature : les deux causes redeviennent indiscernables");
    console.log(`[cas] la ligne ouvre et referme le même cas (aria-expanded ${depart.deplie} -> true -> false), le bouton du détail emprunte le même chemin et repeint la ligne, un cas terminé rend un statut inerte qui nomme sa raison et sa sortie, un cas en cours ne la porte pas, et un droit manquant se dit autrement`);
  } finally {
    document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine; S.AUTH = null; S.caseSelectedId = null;
  }
}

// ---------------------------------------------------------------------------------------------
// 22. CE QUE LA CONSOLE SAVAIT DÉJÀ FAIRE SUR UNE RÈGLE (`P11.12-a`, mesure). La clé affirmait que le
//     panneau des règles « ne s'édite pas depuis la console ». Ce témoin est VERT AVANT toute correction :
//     la ligne d'une règle rend DÉJÀ « Tester », « Éditer » et « Supprimer », et l'interrupteur d'activation
//     partagé (`producer_ui.js`) y est actif pour un administrateur ; `index.html` porte DÉJÀ le bouton de
//     création. C'est lui qui interdit de raconter que la création, la modification, le retrait ou
//     l'activation manquaient : ce qui manquait est la RECHERCHE, et rien d'autre.
//     Le témoin inverse (un lecteur) prouve que la mesure lit bien le rôle : l'interrupteur d'une règle est
//     alors inerte, et il dit pourquoi — une version qui rendrait TOUJOURS un interrupteur actif ne passerait
//     pas les deux.
// ---------------------------------------------------------------------------------------------
{
  const { ruleRow } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const regle = { id: 3, name: "SSH brute force", enabled: 1, query: "search source=sshd failed | stats count", is_soql: 1, op: ">", threshold: 10, severity: 3, interval_s: 300, window_s: 600, last_run: 0, last_value: null, last_fired: null, mitre: "T1110", managed: 2, compliance: "", risk_score: 0 };
  const roleOrigine = S.AUTH;
  try {
    S.AUTH = { user: "root", role: "admin" };
    const ligne = ruleRow(regle);
    const etiquettes = cueillir(ligne, (e) => e.tagName === "BUTTON", []).map((b) => (b.textContent || "") + " " + (b.title || ""));
    for (const geste of ["Tester", "Éditer", "Supprimer"]) {
      exiger(etiquettes.some((l) => l.includes(geste)), `(22) la ligne d'une règle ne rend AUCUN geste « ${geste} » : ${JSON.stringify(etiquettes)}`);
    }
    const interrupteur = cueillir(ligne, (e) => e.tagName === "INPUT" && e.classList && e.classList.contains("crud-toggle"), [])[0];
    exiger(!!interrupteur, "(22) la ligne d'une règle ne rend aucun interrupteur d'activation");
    exiger(interrupteur && interrupteur.disabled !== true, "(22) l'interrupteur d'activation est inerte pour un ADMINISTRATEUR : l'activation ne serait pas atteignable depuis la console");
    const html = readFileSync(path.join(WEB, "index.html"), "utf8");
    exiger(/id="rule-new"/.test(html), "(22) index.html ne porte aucun bouton de création de règle : la création manquerait vraiment");

    // témoin inverse — un lecteur : l'interrupteur est inerte, et la raison est écrite à côté.
    S.AUTH = { user: "bob", role: "viewer" };
    const ligneLecteur = ruleRow(regle);
    const interrupteurLecteur = cueillir(ligneLecteur, (e) => e.tagName === "INPUT" && e.classList && e.classList.contains("crud-toggle"), [])[0];
    exiger(interrupteurLecteur && interrupteurLecteur.disabled === true, "(22) témoin inverse : un lecteur obtient un interrupteur ACTIF — la mesure ne lit pas le rôle");
    const etiquetteLecteur = cueillir(ligneLecteur, (e) => e.tagName === "LABEL" && e.classList && e.classList.contains("producer-switch"), [])[0];
    exiger(etiquetteLecteur && /administrateur/.test(etiquetteLecteur.title || ""), `(22) témoin inverse : l'interrupteur inerte d'un lecteur ne dit pas pourquoi — « ${etiquetteLecteur && etiquetteLecteur.title} »`);
    console.log(`[règles] mesure : la ligne d'une règle rend déjà tester / éditer / supprimer et un interrupteur actif pour un administrateur, inerte et motivé pour un lecteur ; index.html porte le bouton de création`);
  } finally {
    S.AUTH = roleOrigine;
  }
}

// ---------------------------------------------------------------------------------------------
// 23. LA RECHERCHE D'UNE LISTE EST UN MÉCANISME PARTAGÉ, ET ELLE SE COMPOSE (`P11.12-a`).
//     (a) LE PRÉDICAT. Recherche vide = la liste entière (une recherche qui n'est pas faite ne cache
//         rien) ; plusieurs mots = ET (ajouter un mot RESSERRE) ; casse et accents indifférents.
//     (b) CE QU'UNE RÈGLE OFFRE À LA RECHERCHE : son nom, sa requête, l'identifiant de la technique ET
//         son nom. Chacun est jugé SÉPARÉMENT — un texte cherchable qui aurait perdu la requête ou la
//         technique passerait un témoin qui ne chercherait que par le nom.
//     (c) LA COMPOSITION. Recherche vide -> le groupement repliable par gravité, comme avant. Recherche
//         posée -> une liste de RÉSULTATS plate, ordonnée par le tri COURANT (le tri n'est pas remplacé),
//         précédée du compte « trouvées / total » : une liste qui cache des lignes le dit.
//     (d) L'ABSENCE DE RÉSULTAT SE DIT, et elle dit CE QUI est cherché — sinon elle est indevinable.
//     (e) LE CHAMP EST LE MÊME PARTOUT : le câblage partagé pose le chrome `.field` et Échap vide.
// ---------------------------------------------------------------------------------------------
{
  const rl = await import(pathToFileURL(path.join(WEB, "recherche_de_liste.js")).href);
  const { renderRules, loadRules, poserLaRechercheDesRegles, apresEnregistrementDUneRegle, texteCherchableDUneRegle } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const aLaClasse = (e, c) => e.classList && e.classList.contains(c);

  // (a) le prédicat, sur des lignes nues.
  const lignes = [{ n: "Fenêtre glissante" }, { n: "SSH brute force" }, { n: "brute force RDP" }];
  const texte = (l) => l.n;
  exiger(rl.filtrerParRecherche(lignes, "", texte).length === 3, "(23a) une recherche vide ne rend pas la liste entière");
  exiger(rl.filtrerParRecherche(lignes, "   ", texte).length === 3, "(23a) une recherche d'espaces seuls filtre quelque chose");
  exiger(rl.filtrerParRecherche(lignes, "brute", texte).length === 2, "(23a) un mot ne trouve pas les deux lignes qui le portent");
  exiger(rl.filtrerParRecherche(lignes, "brute ssh", texte).length === 1, "(23a) deux mots ÉLARGISSENT au lieu de resserrer : la recherche est un OU");
  exiger(rl.filtrerParRecherche(lignes, "SSH", texte).length === 1, "(23a) la casse change le résultat");
  exiger(rl.filtrerParRecherche(lignes, "fenetre", texte).length === 1, "(23a) un mot sans accent ne trouve pas le mot accentué");

  // (b) ce qu'une règle offre à la recherche — chaque source jugée séparément.
  const regle = { id: 1, name: "Échecs SSH", query: "search source=sshd failed | stats count", mitre: "T1110.003", severity: 3, managed: 2, enabled: 1, op: ">", threshold: 5, risk_score: 0 };
  const cherchable = texteCherchableDUneRegle(regle);
  for (const [quoi, mot] of [["le nom", "Échecs SSH"], ["la requête", "sshd"], ["l'identifiant de la technique", "T1110.003"], ["le nom de la technique", "Brute Force"]]) {
    exiger(rl.correspondALaRecherche(cherchable, mot), `(23b) ${quoi} n'est pas cherchable : « ${cherchable} »`);
  }
  exiger(rl.correspondALaRecherche(cherchable, "T1110"), "(23b) la technique PARENTE ne trouve pas la règle taguée par une sous-technique : la matrice ATT&CK n'ouvrirait rien");
  exiger(!rl.correspondALaRecherche(cherchable, "T1190"), "(23b) témoin inverse : une technique étrangère trouve la règle — le texte cherchable colle tout");

  // (c)(d) la composition, sur le panneau réel.
  const liste = new Element("div"); liste.id = "rule-list";
  const qsOrigine = document.querySelector, fetchOrigine = globalThis.fetch, triOrigine = S.ruleSort;
  const catalogue = [
    { id: 1, name: "Échecs SSH", query: "search source=sshd failed | stats count", mitre: "T1110", severity: 2, managed: 2, enabled: 1, op: ">", threshold: 5, risk_score: 0, last_value: null },
    { id: 2, name: "Scan de ports", query: "search source=ufw | stats dc(dport) by src_ip", mitre: "T1046", severity: 4, managed: 2, enabled: 1, op: ">", threshold: 15, risk_score: 0, last_value: null },
    { id: 3, name: "Exploitation web", query: "search source=web status>=500 | stats count", mitre: "T1190", severity: 3, managed: 2, enabled: 0, op: ">", threshold: 50, risk_score: 0, last_value: null },
  ];
  document.querySelector = (sel) => (sel === "#rule-list" ? liste : new Element("div"));
  globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ rules: catalogue }) });
  try {
    S.AUTH = { user: "root", role: "admin" };
    S.ruleSort = "sev";
    await loadRules();
    const groupesAvant = cueillir(liste, (e) => aLaClasse(e, "fgroup"), []).length;
    exiger(groupesAvant === 3, `(23c) sans recherche, le groupement repliable par gravité a changé : ${groupesAvant} groupe(s) au lieu de 3`);
    exiger(cueillir(liste, (e) => aLaClasse(e, "recherche-resume"), []).length === 0, "(23c) sans recherche, la liste rend quand même un résumé de recherche");

    poserLaRechercheDesRegles("sshd");
    exiger(cueillir(liste, (e) => aLaClasse(e, "fgroup"), []).length === 0, "(23c) une recherche posée laisse le groupement repliable : une correspondance tombée dans une section repliée resterait invisible");
    const resume = cueillir(liste, (e) => aLaClasse(e, "recherche-resume"), [])[0];
    exiger(!!resume && /1 \/ 3/.test(resume.textContent), `(23c) la liste filtrée ne dit pas combien de lignes sur combien : « ${resume && resume.textContent} »`);
    exiger(!!resume && /le tri reste/.test(resume.textContent), `(23c) le résumé ne dit pas que le tri est conservé : « ${resume && resume.textContent} »`);
    let nomsRendus = cueillir(liste, (e) => aLaClasse(e, "rulename"), []).map((e) => e.textContent);
    exiger(nomsRendus.length === 1 && /Échecs SSH/.test(nomsRendus[0]), `(23c) la recherche par le texte de la REQUÊTE ne rend pas la seule règle attendue : ${JSON.stringify(nomsRendus)}`);

    // le tri courant ordonne les résultats — il n'est pas remplacé par la recherche.
    poserLaRechercheDesRegles("search");
    nomsRendus = cueillir(liste, (e) => aLaClasse(e, "rulename"), []).map((e) => e.textContent.replace(/\s+/g, " ").trim());
    exiger(nomsRendus.length === 3, `(23c) instrument : la recherche large ne rend pas les trois règles (${nomsRendus.length})`);
    exiger(/^Scan de ports/.test(nomsRendus[0]) && /^Échecs SSH/.test(nomsRendus[2]), `(23c) le tri « gravité » n'ordonne PAS les résultats de la recherche : ${JSON.stringify(nomsRendus)}`);
    S.ruleSort = "id";
    renderRules();
    nomsRendus = cueillir(liste, (e) => aLaClasse(e, "rulename"), []).map((e) => e.textContent.replace(/\s+/g, " ").trim());
    exiger(/^Échecs SSH/.test(nomsRendus[0]), `(23c) changer le tri ne réordonne pas les résultats : ${JSON.stringify(nomsRendus)}`);

    // (d) aucun résultat : la liste le dit, et dit ce qu'elle a cherché.
    poserLaRechercheDesRegles("kerberoasting");
    const vide = cueillir(liste, (e) => aLaClasse(e, "recherche-resume"), [])[0];
    exiger(!!vide && /Aucune règle/.test(vide.textContent), `(23d) une recherche sans résultat ne dit rien : « ${vide && vide.textContent} »`);
    exiger(!!vide && /nom/.test(vide.textContent) && /requête/.test(vide.textContent) && /ATT&CK/.test(vide.textContent), `(23d) l'absence de résultat ne dit pas CE QUI est cherché : « ${vide && vide.textContent} »`);
    exiger(cueillir(liste, (e) => aLaClasse(e, "rulerow"), []).length === 0, "(23d) une recherche sans résultat rend quand même des lignes");

    // retour à l'état de départ : vider la recherche rend le groupement.
    poserLaRechercheDesRegles("");
    exiger(cueillir(liste, (e) => aLaClasse(e, "fgroup"), []).length === 3, "(23c) vider la recherche ne rend pas le groupement par gravité");

    // (f) UNE RÈGLE ENREGISTRÉE SE VOIT : le retour d'un enregistrement vide la recherche, sinon le geste
    //     réussirait dans une liste qui n'en montre rien.
    poserLaRechercheDesRegles("kerberoasting");
    exiger(cueillir(liste, (e) => aLaClasse(e, "rulerow"), []).length === 0, "(23f) instrument : la recherche de départ montre encore des règles, la suite ne prouverait rien");
    await apresEnregistrementDUneRegle();
    exiger(cueillir(liste, (e) => aLaClasse(e, "fgroup"), []).length === 3, "(23f) après un enregistrement, la recherche filtre encore : la règle qu'on vient d'écrire reste invisible");
    exiger(cueillir(liste, (e) => aLaClasse(e, "recherche-resume"), []).length === 0, "(23f) après un enregistrement, la liste dit encore qu'elle est filtrée");

    // (e) le champ partagé : chrome posé, Échap vide, et le rendu suit.
    const champ = new Element("input"); champ.value = "";
    const ecouteurs = {};
    champ.addEventListener = (type, fn) => { (ecouteurs[type] = ecouteurs[type] || []).push(fn); };
    let vus = [];
    const poignee = rl.champDeRecherche(champ, { auChangement: (v) => vus.push(v) });
    exiger(champ.classList.contains("field"), "(23e) le champ de recherche partagé ne prend pas le chrome `.field` : il retombe au cadre natif du navigateur");
    champ.value = "ssh"; (ecouteurs.input || []).forEach((f) => f());
    exiger(poignee.valeur() === "ssh" && vus[vus.length - 1] === "ssh", `(23e) la frappe n'atteint pas le rendu : ${JSON.stringify(vus)}`);
    (ecouteurs.keydown || []).forEach((f) => f({ key: "Escape" }));
    exiger(champ.value === "" && vus[vus.length - 1] === "", `(23e) Échap ne vide pas la recherche : « ${champ.value} », ${JSON.stringify(vus)}`);
    console.log(`[recherche] prédicat ET multi-mots insensible à la casse et aux accents ; une règle se cherche par son nom, sa requête, l'identifiant de sa technique et le nom de celle-ci ; la recherche posée rend une liste plate ordonnée par le tri courant avec le compte « trouvées / total », l'absence de résultat dit ce qui est cherché, et vider rend le groupement`);
  } finally {
    document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine; S.ruleSort = triOrigine; S.AUTH = null;
  }
}

// ---------------------------------------------------------------------------------------------
// 24. UNE TECHNIQUE ATT&CK EST UNE PORTE (`P11.6-b`).
//     (a) VERT AVANT : la console NE FABRIQUE AUCUNE REQUÊTE pour une technique. Le chemin vers les
//         détections est le pivot qui existait déjà (`setAlertMitreFilter`, `P11.1-b`), et de là le lien
//         exact est celui que le démon sert avec l'alerte (`P11.1-a`). Ce témoin lit le module : aucune
//         requête montée à la main, aucune écriture dans la barre de recherche. Il tient avant comme
//         après, et c'est lui qui interdit d'inventer une seconde construction de requête.
//     (b) La porte d'une technique COUVERTE rend ses trois sorties, et dit combien de règles la couvrent.
//     (c) La porte d'un ANGLE MORT le dit, met la CRÉATION en avant, et rend la sortie « voir les règles »
//         inerte AVEC sa raison — une sortie retirée ne se distinguerait pas d'une sortie oubliée.
//     (d) Les sorties MÈNENT : celle des règles et celle de la création appellent le panneau des règles
//         sur CETTE technique, celle des détections pose la facette de la technique sur la file d'alertes.
//     (e) Un lecteur voit la sortie de création, inerte, et le motif nomme le RÔLE — pas un état.
//     (f) LE TROISIÈME ÉTAT (`P9.5-a`) : une règle EXISTE et est ACTIVÉE, mais rien sur cette base ne
//         peut la nourrir. C'est le défaut que la correction précédente avait RETOURNÉ au lieu de le
//         fermer : la matrice cessait — à raison — de compter la technique couverte, mais la console la
//         rendait avec le vocabulaire de l'ABSENCE (« aucune règle activée ne couvre cette technique »),
//         rendait INERTE la sortie vers la règle, et mettait « créer la règle » en avant. Les trois
//         étaient faux, et le geste prescrit était nuisible. Ce témoin exige que l'état soit rendu
//         DISTINCT des deux autres, que la RAISON (la source qui manque) soit NOMMÉE, que la sortie vers
//         la règle soit PRATICABLE et MÈNE, et que l'import Sigma — qui ne branche aucun producteur — ne
//         soit plus proposé. Il lit AUSSI le démon : sans les deux clés servies, cet état serait
//         inatteignable et le vert ne prouverait rien du geste réellement servi.
// ---------------------------------------------------------------------------------------------
{
  const { porteDeLaTechnique, poserLesPortesDeTechnique, techniqueCell } = await import(pathToFileURL(path.join(WEB, "attack.js")).href);
  const { ouvrirLesReglesDeLaTechnique, ouvrirLaCreationPourLaTechnique } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const sorties = (el) => cueillir(el, (e) => e.tagName === "BUTTON", []);
  const parLibelle = (el, motif) => sorties(el).find((b) => motif.test(b.textContent));

  // (a) aucune requête fabriquée ici.
  const source = readFileSync(path.join(WEB, "attack.js"), "utf8");
  exiger(!/['"`]\s*search\s/i.test(source), "(24a) `attack.js` monte une requête à la main : le lien vers les détections doit rester le pivot existant, et la requête exacte celle que le démon sert avec l'alerte");
  exiger(!/#sql/.test(source), "(24a) `attack.js` écrit dans la barre de recherche : la console fabriquerait une seconde construction de requête");
  exiger(/setAlertMitreFilter/.test(source), "(24a) instrument : le module n'appelle plus le pivot existant, les deux assertions ci-dessus ne prouveraient rien");

  const roleOrigine = S.AUTH, hashOrigine = location.hash, fetchOrigine = globalThis.fetch;
  const vus = [];
  try {
    S.AUTH = { user: "root", role: "admin" };
    poserLesPortesDeTechnique({ regles: (t) => vus.push("regles:" + t), creer: (t) => vus.push("creer:" + t) });

    // (b) technique couverte.
    const couverte = { tid: "T1110", name: "Brute Force", covered: true, rule_count: 3, alert_count: 12 };
    const porte = porteDeLaTechnique(couverte);
    exiger(/T1110/.test(porte.textContent) && /Brute Force/.test(porte.textContent), `(24b) la porte ne nomme pas la technique : « ${porte.textContent} »`);
    exiger(/3 règle\(s\) la couvrent/.test(porte.textContent), `(24b) la porte ne dit pas combien de règles couvrent la technique : « ${porte.textContent} »`);
    for (const [quoi, motif] of [["les règles", /règles qui la couvrent/], ["les détections", /détections de cette technique/], ["la création", /règle sur cette technique|règle qui la couvrira/]]) {
      const b = parLibelle(porte, motif);
      exiger(!!b, `(24b) la porte d'une technique couverte n'offre AUCUNE sortie vers ${quoi} : ${JSON.stringify(sorties(porte).map((x) => x.textContent))}`);
      exiger(b && b.disabled !== true, `(24b) la sortie vers ${quoi} est inerte alors que la technique est couverte`);
    }

    // (c) angle mort.
    const aveugle = { tid: "T1552", name: "Unsecured Credentials", covered: false, rule_count: 0, alert_count: 0 };
    const porteAveugle = porteDeLaTechnique(aveugle);
    exiger(/ANGLE MORT/.test(porteAveugle.textContent), `(24c) un angle mort ne se dit pas dans sa porte : « ${porteAveugle.textContent} »`);
    const versRegles = parLibelle(porteAveugle, /règles qui la couvrent/);
    exiger(versRegles && versRegles.disabled === true, "(24c) la sortie « voir les règles » d'un angle mort n'est pas inerte : elle ouvrirait une liste vide");
    exiger(versRegles && /Aucune règle ne couvre/.test(versRegles.title || ""), `(24c) la sortie inerte ne dit pas POURQUOI : « ${versRegles && versRegles.title} »`);
    const versCreation = parLibelle(porteAveugle, /Créer la règle qui la couvrira/);
    exiger(!!versCreation && versCreation.classList.contains("btn-primary"), "(24c) sur un angle mort, la création n'est pas la sortie mise en avant");
    exiger(!!parLibelle(porteAveugle, /ruleset Sigma/), "(24c) un administrateur ne se voit pas offrir l'import Sigma depuis la porte d'un angle mort");

    // (d) les sorties mènent.
    // les clics sont défensifs : une sortie disparue doit RAPPORTER (témoins ci-dessus) et non faire
    // tomber le harnais avant qu'il n'imprime ce qu'il a relevé.
    parLibelle(porte, /règles qui la couvrent/)?.onclick?.();
    parLibelle(porteAveugle, /Créer la règle qui la couvrira/)?.onclick?.();
    exiger(vus.join(" ") === "regles:T1110 creer:T1552", `(24d) les sorties n'appellent pas le panneau des règles sur CETTE technique : ${JSON.stringify(vus)}`);
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ alerts: [], total: 0, groups: [] }) });
    S.alertMitreFilter = "";
    parLibelle(porte, /détections de cette technique/)?.onclick?.();
    exiger(S.alertMitreFilter === "T1110", `(24d) la sortie « détections » ne pose pas la facette de la technique sur la file d'alertes : « ${S.alertMitreFilter} »`);
    exiger(/^#?alerts$/.test(location.hash), `(24d) la sortie « détections » ne mène pas aux alertes : « ${location.hash} »`);

    // (e) un lecteur : la création est rendue, inerte, et le motif nomme le rôle.
    S.AUTH = { user: "bob", role: "viewer" };
    const porteLecteur = porteDeLaTechnique(aveugle);
    const creationLecteur = parLibelle(porteLecteur, /Créer la règle qui la couvrira/);
    exiger(!!creationLecteur, "(24e) un lecteur ne voit AUCUNE sortie de création : le droit manquant devient indevinable");
    exiger(creationLecteur && creationLecteur.disabled === true, "(24e) un lecteur obtient une sortie de création praticable : la garde d'interface ne lit pas le rôle");
    exiger(creationLecteur && /rôle éditeur/.test(creationLecteur.title || ""), `(24e) le motif ne nomme pas le rôle qui manque : « ${creationLecteur && creationLecteur.title} »`);
    exiger(!parLibelle(porteLecteur, /ruleset Sigma/), "(24e) témoin inverse : un lecteur se voit offrir l'import Sigma, réservé à l'administrateur");

    // (f) LE TROISIÈME ÉTAT. L'INSTRUMENT D'ABORD : le démon sert-il les deux clés ? Sans elles, cet
    //     état n'est atteignable par aucune réponse réelle et tout ce qui suit ne jugerait qu'un objet
    //     fabriqué ici.
    const srcMat = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "alerts.rs"), "utf8");
    const corpsMat = srcMat.match(/fn build_attack_matrix\([\s\S]*?\n\}/);
    exiger(!!corpsMat && /"rules_en_attente_de_source"/.test(corpsMat[0]) && /"sources_manquantes"/.test(corpsMat[0]),
      "(24f) instrument : `build_attack_matrix` ne sert plus le compte des règles en attente de source ET les sources qui manquent — le troisième état serait inatteignable, et ce témoin jugerait un objet que rien ne produit");
    const srcLecture = readFileSync(path.join(RACINE, "daemon", "src", "detection_aveugle.rs"), "utf8");
    exiger(/en_attente_de_source\.push\(\(mitre, manquantes\)\)/.test(srcLecture),
      "(24f) instrument : la lecture du démon ne pousse plus la RAISON à côté du tag — elle est calculée là où le filtre décide, et la jeter est exactement le défaut que ce témoin poursuit");

    S.AUTH = { user: "root", role: "admin" };
    const enAttente = { tid: "T1552", name: "Unsecured Credentials", covered: false, rule_count: 0, alert_count: 0,
      rules_en_attente_de_source: 1, sources_manquantes: ["vault-audit"] };
    const porteAttente = porteDeLaTechnique(enAttente);
    const texteAttente = porteAttente.textContent;
    exiger(!/ANGLE MORT/.test(texteAttente),
      `(24f) une technique dont la règle EXISTE et est ACTIVÉE est rendue comme un angle mort : « ${texteAttente} »`);
    exiger(/ACTIVÉES/.test(texteAttente) && /vault-audit/.test(texteAttente),
      `(24f) l'état ne dit pas que la règle est activée, ou ne NOMME pas la source qui manque — c'est le seul renseignement actionnable : « ${texteAttente} »`);
    const versReglesAttente = parLibelle(porteAttente, /règles qui attendent leur source/);
    exiger(!!versReglesAttente, `(24f) aucune sortie vers la règle qui attend sa source : ${JSON.stringify(sorties(porteAttente).map((x) => x.textContent))}`);
    exiger(versReglesAttente && versReglesAttente.disabled !== true,
      "(24f) la sortie vers la règle est INERTE alors que la règle existe et est activée : la console déclare inexistant ce qu'elle sert dans le panneau voisin");
    exiger(versReglesAttente && versReglesAttente.classList.contains("btn-primary"),
      "(24f) la sortie mise en avant n'est pas celle qui MÈNE À LA RÈGLE : c'est le seul geste que la console peut porter ici");
    const creationAttente = parLibelle(porteAttente, /Créer la règle qui la couvrira/);
    exiger(!creationAttente, "(24f) la console propose encore de « créer la règle qui la couvrira » : la règle est là — c'est son producteur qui manque, et une seconde règle sans épinglage la ré-annoncerait couverte sans que rien ne tire");
    const ajoutAttente = parLibelle(porteAttente, /Ajouter une règle sur cette technique/);
    exiger(!!ajoutAttente && !ajoutAttente.classList.contains("btn-primary"),
      "(24f) écrire une règle de plus est mis en avant sur une technique qui attend son producteur : c'est le mauvais geste, prescrit en premier");
    exiger(!parLibelle(porteAttente, /ruleset Sigma/),
      "(24f) l'import Sigma est proposé sur une technique qui attend sa source : importer une bibliothèque n'a jamais branché un producteur");

    // ET LA SORTIE MÈNE VRAIMENT — la même mesure que (24d), sur ce troisième état.
    vus.length = 0;
    versReglesAttente?.onclick?.();
    exiger(vus.join(" ") === "regles:T1552", `(24f) la sortie vers la règle n'appelle pas le panneau des règles sur CETTE technique : ${JSON.stringify(vus)}`);

    // LA CELLULE AUSSI : trois états, trois rendus. Le témoin NÉGATIF est la cellule d'un VRAI angle
    // mort — sans lui, « la cellule le dit » se prouverait sur une marque que toute cellule porterait.
    const celluleAttente = techniqueCell(enAttente, 3);
    const celluleAveugle = techniqueCell(aveugle, 3);
    exiger(celluleAttente.classList.contains("attente") && !celluleAttente.classList.contains("uncovered"),
      `(24f) la cellule en attente de source porte l'habillage du vide : « ${celluleAttente.className} »`);
    exiger(celluleAveugle.classList.contains("uncovered") && !celluleAveugle.classList.contains("attente"),
      `(24f) témoin négatif : un VRAI angle mort porte l'habillage du troisième état : « ${celluleAveugle.className} »`);
    exiger(/vault-audit/.test(celluleAttente.title || ""), `(24f) le survol de la cellule ne nomme pas la source à brancher : « ${celluleAttente.title} »`);
    exiger(!/vault-audit/.test(celluleAveugle.title || "") && /ANGLE MORT/.test(celluleAveugle.title || ""),
      `(24f) témoin négatif : le survol d'un vrai angle mort ne dit plus « angle mort », ou nomme une source : « ${celluleAveugle.title} »`);

    console.log(`[ATT&CK] une technique ouvre une porte : ses règles, ses détections (le pivot existant, aucune requête fabriquée) et le geste qui la couvrirait ; un angle mort le dit, met la création en avant et rend la sortie vide inerte avec son motif ; un lecteur voit la création inerte, motivée par le rôle. ET UN TROISIÈME ÉTAT, lu de bout en bout (le démon sert le compte des règles en attente ET les sources qui manquent ; la console les rend) : une technique dont la règle EXISTE et est ACTIVÉE mais que rien ne nourrit n'est PLUS annoncée « aucune règle » — elle NOMME la source à brancher, la sortie vers la règle est praticable, mise en avant, et elle MÈNE ; « créer la règle qui la couvrira » et l'import Sigma, qui ne branchent aucun producteur, ne sont plus proposés ; et la cellule porte un habillage que le vrai angle mort ne porte pas, ce que le témoin négatif vérifie dans l'autre sens. CE QUE CE TÉMOIN NE TIENT PAS : l'encre réellement peinte (le simulacre ne lit aucun style calculé), et le fait qu'une règle en attente soit RETROUVÉE par la recherche du panneau des règles — il tient que la sortie l'appelle sur la technique, pas ce que ce panneau en fait.`);
  } finally {
    poserLesPortesDeTechnique({ regles: ouvrirLesReglesDeLaTechnique, creer: ouvrirLaCreationPourLaTechnique });
    S.AUTH = roleOrigine; location.hash = hashOrigine; globalThis.fetch = fetchOrigine; S.alertMitreFilter = "";
  }
}

// ---------------------------------------------------------------------------------------------
// 25. UN FILTRE CHOISI SE MARQUE PAR UN MOYEN RÉSERVÉ, PAS PAR LA GRAISSE DU MOT (`P11.4-i`).
//     MESURE (2026-08-23, style.css) : `.alertview .agseg.on` et `.agscope.on` portaient `font-weight:600`,
//     alors que le gras dit ailleurs « alarme » ou « valeur remarquable ». Le témoin juge les DEUX moitiés
//     de la correction, et il les juge à leur source respective :
//       (a) la FEUILLE — aucun état choisi de la barre ne porte de graisse, et le liseré réservé y est
//           employé ; le témoin lit le fichier, parce que le défaut EST une déclaration de style ;
//       (b) le RENDU — l'état choisi est DIT (`aria-pressed`), sur les deux valeurs, et le mot rendu est
//           le MÊME choisi ou non : seul l'habillage change.
// ---------------------------------------------------------------------------------------------
{
  const { alertActionBarHtml } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const css = readFileSync(path.join(WEB, "style.css"), "utf8");
  const regle = (sel) => (css.match(new RegExp(`(^|\\n)${sel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\{([^}]*)\\}`)) || [])[2] || "";
  // (a) la feuille. Instrument d'abord : les deux règles existent, sinon la suite jugerait le vide.
  const etatsChoisis = [".alertview .agseg.on", ".agscope.on"];
  for (const sel of etatsChoisis) exiger(regle(sel).length > 0, `(25a) instrument : la règle « ${sel} » est introuvable dans style.css, le témoin jugerait une chaîne vide`);
  for (const sel of etatsChoisis) exiger(!/font-weight/.test(regle(sel)), `(25a) « ${sel} » marque encore l'état choisi par la graisse du mot : « ${regle(sel)} »`);
  for (const sel of etatsChoisis) exiger(/var\(--sel-ring\)/.test(regle(sel)), `(25a) « ${sel} » n'emploie pas le moyen réservé à l'état choisi : « ${regle(sel)} »`);
  // Le moyen est RÉSERVÉ : `--sel-ring` est déclaré une fois et n'est lu que par les états choisis.
  const lecteurs = [...css.matchAll(/(^|\n)([^\n{]+)\{[^}]*var\(--sel-ring\)[^}]*\}/g)].map((m) => m[2].trim());
  exiger(lecteurs.length === etatsChoisis.length && lecteurs.every((l) => etatsChoisis.includes(l)), `(25a) le moyen réservé à « choisi » est employé ailleurs : ${JSON.stringify(lecteurs)}`);
  // (b) le rendu. Le mot ne change pas, l'état est dit — dans les deux sens.
  const libelleDe = (html, motif) => ((html.match(new RegExp(`<button[^>]*${motif}[^>]*>([^<]*)</button>`)) || [])[1] || "").trim();
  const boutonDe = (html, motif) => (html.match(new RegExp(`<button[^>]*${motif}[^>]*>`)) || [])[0] || "";
  const charges = { count: 3, countLabel: "3 alerte(s)", ackableIds: [1, 2, 3] };
  const nu = { view: "", scopeAll: false, uncased: true, mitre: "", source: "" };
  const surRegle = alertActionBarHtml({ ...nu, view: "rule" }, charges), surPlate = alertActionBarHtml(nu, charges);
  exiger(libelleDe(surRegle, 'data-g="rule"') === libelleDe(surPlate, 'data-g="rule"') && libelleDe(surPlate, 'data-g="rule"').length > 0, `(25b) le MOT d'un tri change selon qu'il est choisi ou non : « ${libelleDe(surRegle, 'data-g="rule"')} » / « ${libelleDe(surPlate, 'data-g="rule"')} »`);
  exiger(/aria-pressed="true"/.test(boutonDe(surRegle, 'data-g="rule"')), `(25b) le tri choisi ne DIT pas qu'il l'est : ${boutonDe(surRegle, 'data-g="rule"')}`);
  exiger(/aria-pressed="false"/.test(boutonDe(surPlate, 'data-g="rule"')), `(25b) un tri NON choisi ne dit rien : un bouton bascule sans attribut se lit comme un bouton d'action — ${boutonDe(surPlate, 'data-g="rule"')}`);
  for (const [motif, quoi] of [['data-act="scope"', "la portée"], ['data-act="uncased"', "le filtre de ce qui est listé"]]) {
    exiger(/aria-pressed="(true|false)"/.test(boutonDe(surPlate, motif)), `(25b) ${quoi} ne dit pas son état : ${boutonDe(surPlate, motif)}`);
  }
  const porteeTous = alertActionBarHtml({ ...nu, scopeAll: true }, charges);
  exiger(/aria-pressed="true"/.test(boutonDe(porteeTous, 'data-act="scope"')) && /aria-pressed="false"/.test(boutonDe(surPlate, 'data-act="scope"')), "(25b) l'état dit de la portée ne SUIT pas le modèle");
  console.log(`[filtres] aucun état choisi de la barre des alertes ne passe par la graisse du mot ; le liseré réservé n'est lu que par ces deux règles, le mot rendu est le même choisi ou non, et l'état est dit par aria-pressed dans les deux sens`);
}


// ---------------------------------------------------------------------------------------------
// 26. UN ESPACE ANNONCE CE QU'IL CONTIENT, ET UN FILTRE SE NOMME PAR CE QU'IL MONTRE (`P11.7-b`).
//     (a) LA PROPRIÉTÉ EST DÉRIVÉE, PAS ÉNUMÉRÉE : un espace qui porte PLUSIEURS onglets ne peut pas
//         s'appeler comme UN SEUL d'entre eux — le lecteur en conclurait que les autres sont ailleurs.
//         C'était exactement le défaut : l'espace « Cas » portait les onglets « Alertes » ET « Cas ».
//         Le témoin balaie TOUS les espaces, donc un futur espace à deux onglets tombera dessus aussi.
//     (b) LE FILTRE DE LA LISTE DES ALERTES est nommé par ce qu'il MONTRE, dans les deux états, et le
//         COMPTE affiché emploie les mêmes mots que le bouton — les deux vues (plate et groupée) tirant
//         désormais d'un seul auteur, un renommage ne peut plus n'en atteindre qu'une.
//     (c) L'ANCIEN VOCABULAIRE A DISPARU DE LA SURFACE : « hors case » et « cases comprises » ne sont
//         rendus par aucun des deux états, ni par aucune des deux vues.
// ---------------------------------------------------------------------------------------------
{
  const { SPACES } = await import(pathToFileURL(path.join(WEB, "app.js")).href);
  const { alertActionBarHtml } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const html = readFileSync(path.join(WEB, "index.html"), "utf8");
  const nav = html.slice(html.indexOf('<nav class="sidebar"'), html.indexOf("</nav>"));
  const motLu = (t) => t.replace(/&amp;/g, "&").trim().toLowerCase();
  const libelles = new Map([...nav.matchAll(/data-space="([a-z-]+)"[^>]*>[\s\S]*?<span>([^<]*)<\/span>/g)].map((m) => [m[1], motLu(m[2])]));
  const multi = SPACES.filter((sp) => sp.tabs.length > 1);
  exiger(multi.length >= 3, `(26a) instrument : ${multi.length} espace(s) à plusieurs onglets, la propriété ne serait exercée sur presque rien`);
  const usurpes = multi
    .map((sp) => ({ id: sp.id, libelle: libelles.get(sp.id), onglet: sp.tabs.find((t) => motLu(t.label) === libelles.get(sp.id)) }))
    .filter((x) => x.onglet);
  exiger(usurpes.length === 0, `(26a) un espace à plusieurs onglets porte le nom d'UN SEUL d'entre eux — les autres se lisent comme absents : ${usurpes.map((x) => `${x.id} → « ${x.libelle} »`).join(", ")}`);
  exiger(libelles.get("cases") === "alertes & cas", `(26a) l'espace qui porte alertes et cas ne les annonce pas : « ${libelles.get("cases")} »`);
  // (b)(c) le filtre, dans ses deux états.
  const charges = { count: 3, countLabel: "3 alerte(s)", ackableIds: [1, 2, 3] };
  const libelleBouton = (h) => ((h.match(/<button[^>]*data-act="uncased"[^>]*>([^<]*)<\/button>/) || [])[1] || "").trim();
  const survolBouton = (h) => ((h.match(/<button[^>]*data-act="uncased"[^>]*title="([^"]*)"/) || [])[1] || "");
  const sansCas = alertActionBarHtml({ view: "", scopeAll: false, uncased: true, mitre: "", source: "" }, charges);
  const avecCas = alertActionBarHtml({ view: "", scopeAll: false, uncased: false, mitre: "", source: "" }, charges);
  exiger(libelleBouton(sansCas) === "Pas encore dans un cas", `(26b) l'état par défaut ne dit pas CE QUI est listé : « ${libelleBouton(sansCas)} »`);
  exiger(libelleBouton(avecCas) === "Toutes les alertes", `(26b) l'autre état ne dit pas CE QUI est listé : « ${libelleBouton(avecCas)} »`);
  exiger(/liste|list[ée]/.test(survolBouton(sansCas)) && /liste|list[ée]/.test(survolBouton(avecCas)), `(26b) le survol ne parle pas de ce qui est LISTÉ : « ${survolBouton(sansCas)} » / « ${survolBouton(avecCas)} »`);
  exiger(/Affiche/.test(sansCas), "(26b) le filtre n'est pas rattaché à la liste par un mot d'entrée, là où le tri et la portée le sont");
  for (const [quoi, h] of [["l'état par défaut", sansCas], ["l'autre état", avecCas]]) {
    exiger(!/hors case|cases comprises/.test(h), `(26c) ${quoi} rend encore la relation implicite d'origine : ${h.match(/<button[^>]*data-act="uncased"[^>]*>[^<]*<\/button>/)?.[0]}`);
  }
  // Le COMPTE emploie les mêmes mots que le bouton, dans les deux vues (un seul auteur : `porteeEnMots`).
  const source = readFileSync(path.join(WEB, "alerts.js"), "utf8");
  const auteursDeLaPortee = source.match(/\(m\.scopeAll \? 'tous statuts' : 'actives'\)/g) || [];
  exiger(auteursDeLaPortee.length === 1, `(26b) la portée en toutes lettres est écrite ${auteursDeLaPortee.length} fois : un renommage n'atteindrait qu'une des deux vues`);
  console.log(`[espaces] aucun espace à plusieurs onglets ne porte le nom d'un seul d'entre eux ; le filtre de la liste des alertes se nomme par ce qu'il montre dans ses deux états, l'ancienne relation « hors case » a quitté la surface, et la portée en toutes lettres n'a plus qu'un auteur`);
}


// ---------------------------------------------------------------------------------------------
// 27. LES ALERTES SE CHERCHENT, PAR LE MÊME CHAMP QUE LES AUTRES LISTES (`P11.1-f`).
//     (a) CE QU'UNE ALERTE OFFRE À LA RECHERCHE : son titre (qui porte le nom de la règle), le jeton de
//         la règle qui l'a levée, et les sources auxquelles le démon l'a IMPUTÉE — chacun jugé
//         SÉPARÉMENT, sans quoi un texte cherchable amputé passerait un témoin qui ne lit que le titre.
//         Témoin inverse : la technique n'y est PAS (elle a sa facette servie et son chip de pivot).
//     (b) LA COMPOSITION : la recherche s'applique APRÈS le serveur et ne retire aucun filtre ; sous un
//         tri GROUPÉ elle rend une liste plate — les occurrences d'un groupe ne sont même pas chargées,
//         une correspondance tombée dedans serait invisible ET introuvable (même choix qu'aux règles) —
//         et le groupement revient dès qu'elle est vidée.
//     (c) CE QUE LA LISTE DIT D'ELLE-MÊME : combien de lignes sur combien, et CE QUE LA RECHERCHE COUVRE
//         — les alertes servies, ou la seule page affichée sous la portée paginée. La phrase change avec
//         la portée : une recherche qui laisserait croire qu'elle a lu tout l'historique mentirait.
//     (d) CE QUE LA BARRE PROMET SUIT LA RECHERCHE : l'acquittement global (qui dépasse la page)
//         disparaît, l'acquittement par liste compte les alertes AFFICHÉES, et l'export les emporte.
// ---------------------------------------------------------------------------------------------
{
  const { dessinerLaListePlate, alertListModel, poserLaRechercheDesAlertes, texteCherchableDUneAlerte, renderAlerts } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const rl = await import(pathToFileURL(path.join(WEB, "recherche_de_liste.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  // (a) le texte cherchable, source par source.
  const alerte = { id: 7, ts: 1000, rule: "rule.12", severity: 3, title: "Échecs SSH : 42 > 5", status: "new", detail: "search source=sshd failed | stats count", mitre: "T1110", sources: "sshd-session\nauthlog", case_id: null, acked_at: 0, acked_by: "" };
  const cherchable = texteCherchableDUneAlerte(alerte);
  for (const [quoi, mot] of [["le titre (donc le nom de la règle)", "Échecs SSH"], ["le jeton de la règle", "rule.12"], ["la première source imputée", "sshd-session"], ["la seconde source imputée", "authlog"]]) {
    exiger(rl.correspondALaRecherche(cherchable, mot), `(27a) ${quoi} n'est pas cherchable : « ${cherchable} »`);
  }
  exiger(!/sshd-sessionauthlog/.test(cherchable), `(27a) deux sources imputées se collent en un mot que rien ne trouve : « ${cherchable} »`);
  exiger(!rl.correspondALaRecherche(cherchable, "T1110"), "(27a) la technique entre dans le texte cherchable : elle a déjà sa facette servie et son chip de pivot, la remettre ferait remonter tout un pan du catalogue");
  exiger(!rl.correspondALaRecherche(cherchable, "kerberoasting"), "(27a) témoin inverse : un mot étranger trouve l'alerte, le texte cherchable colle tout");

  const liste = new Element("div");
  const qsOrigine = document.querySelector, fetchOrigine = globalThis.fetch;
  const etatOrigine = { g: S.alertGroupBy, a: S.alertGroupAll, u: S.alertUncased, auth: S.AUTH };
  const lot = [
    alerte,
    { id: 8, ts: 900, rule: "heartbeat.auditd", severity: 4, title: "Capteur muet : auditd", status: "new", detail: "aucune donnée depuis 30 min", mitre: "", sources: "auditd", case_id: null, acked_at: 0, acked_by: "" },
    { id: 9, ts: 800, rule: "rule.3", severity: 2, title: "Scan de ports : 60 > 15", status: "new", detail: "search source=ufw", mitre: "T1046", sources: "ufw", case_id: null, acked_at: 0, acked_by: "" },
  ];
  const urlsDemandees = [];
  document.querySelector = (sel) => (sel === "#alerts .body" ? liste : new Element("div"));
  globalThis.fetch = async (u) => { urlsDemandees.push(String(u)); return { ok: true, status: 200, text: async () => JSON.stringify({ alerts: lot, total: 137 }) }; };
  const resume = () => liste.children.find((c) => c.classList && c.classList.contains("recherche-resume"));
  const titresRendus = () => [...String(liste.innerHTML).matchAll(/class="alertdrill"[^>]*>([^<]*)</g)].map((m) => m[1]);
  try {
    S.AUTH = { user: "root", role: "admin" };
    S.alertGroupBy = ""; S.alertGroupAll = false; S.alertUncased = true;
    // sans recherche : les trois lignes, aucun résumé.
    poserLaRechercheDesAlertes("");
    dessinerLaListePlate(liste, alertListModel(), lot, undefined);
    exiger(titresRendus().length === 3, `(27) instrument : ${titresRendus().length} ligne(s) rendues sans recherche au lieu de 3`);
    exiger(!resume(), "(27c) sans recherche, la liste rend quand même un résumé de recherche");
    // (a bis) chercher par le jeton de la règle, puis par une source imputée.
    poserLaRechercheDesAlertes("heartbeat");
    dessinerLaListePlate(liste, alertListModel(), lot, undefined);
    exiger(titresRendus().length === 1 && /auditd/.test(titresRendus()[0]), `(27a) la recherche par le jeton de règle ne rend pas la seule alerte attendue : ${JSON.stringify(titresRendus())}`);
    poserLaRechercheDesAlertes("ufw");
    dessinerLaListePlate(liste, alertListModel(), lot, undefined);
    exiger(titresRendus().length === 1 && /Scan de ports/.test(titresRendus()[0]), `(27a) la recherche par la SOURCE IMPUTÉE ne rend pas la seule alerte attendue : ${JSON.stringify(titresRendus())}`);
    // (c) le résumé : combien sur combien, et ce qu'il couvre — portée « actives ».
    exiger(resume() && /1 \/ 3/.test(resume().textContent), `(27c) la liste filtrée ne dit pas combien de lignes sur combien : « ${resume() && resume().textContent} »`);
    exiger(resume() && /alertes actives servies/.test(resume().textContent), `(27c) le résumé ne dit pas CE QUE la recherche couvre : « ${resume() && resume().textContent} »`);
    exiger(resume() && !/page affichée/.test(resume().textContent), "(27c) sous la portée « actives » (non paginée), le résumé parle pourtant d'une page");
    // (d) la barre suit : plus d'acquittement global, l'acquittement par liste compte les AFFICHÉES.
    exiger(!/data-act="ack-all"/.test(String(liste.innerHTML)), "(27d) sous une recherche, « Tout acquitter » (qui dépasse la page) est encore offert : il dépasserait la recherche");
    exiger(/Acquitter les 1 affichée/.test(String(liste.innerHTML)), `(27d) l'acquittement par liste ne compte pas les alertes AFFICHÉES : ${String(liste.innerHTML).match(/data-act="ack-shown"[^>]*>[^<]*/)?.[0]}`);
    // (c bis) portée paginée : la phrase de couverture change et NOMME la page.
    S.alertGroupAll = true;
    dessinerLaListePlate(liste, alertListModel(), lot, 137);
    exiger(resume() && /page affichée/.test(resume().textContent) && /pas sur tout l'historique/.test(resume().textContent), `(27c) sous la portée paginée, le résumé laisse croire que la recherche a lu tout l'historique : « ${resume() && resume().textContent} »`);
    S.alertGroupAll = false;
    // (c ter) aucun résultat : la liste le dit, nomme ce qu'elle a cherché, et ne rend aucune ligne.
    poserLaRechercheDesAlertes("kerberoasting");
    dessinerLaListePlate(liste, alertListModel(), lot, undefined);
    exiger(titresRendus().length === 0, "(27c) une recherche sans résultat rend quand même des lignes");
    const vide = resume() && resume().textContent;
    exiger(vide && /Aucune alerte/.test(vide) && /titre/.test(vide) && /règle/.test(vide) && /source imputée/.test(vide), `(27c) l'absence de résultat ne dit pas CE QUI est cherché : « ${vide} »`);
    // (b) la composition, sur le chemin réel : tri groupé + recherche -> la liste plate, jamais /alerts/groups.
    S.alertGroupBy = "rule";
    urlsDemandees.length = 0;
    poserLaRechercheDesAlertes("ssh");
    await renderAlerts();
    exiger(urlsDemandees.length === 1 && !/\/alerts\/groups/.test(urlsDemandees[0]), `(27b) sous une recherche, un tri groupé interroge encore la route des groupes : ${JSON.stringify(urlsDemandees)}`);
    exiger(/status=new/.test(urlsDemandees[0]) && /uncased=1/.test(urlsDemandees[0]), `(27b) la recherche a RETIRÉ la portée ou le filtre d'affichage de l'URL au lieu de s'y composer : ${urlsDemandees[0]}`);
    exiger(!/[?&]q=|recherche=/.test(urlsDemandees[0]), `(27b) la recherche est envoyée au démon, qui n'offre aucun paramètre plein-texte : ${urlsDemandees[0]}`);
    exiger(titresRendus().length === 1 && /Échecs SSH/.test(titresRendus()[0]), `(27b) la liste rendue sous recherche n'est pas la liste plate des résultats : ${JSON.stringify(titresRendus())}`);
    // ... et vidée, le groupement revient : la route des groupes est de nouveau celle qui est interrogée.
    urlsDemandees.length = 0;
    poserLaRechercheDesAlertes("");
    await renderAlerts();
    exiger(urlsDemandees.some((u) => /\/alerts\/groups/.test(u)), `(27b) recherche vidée, le groupement ne revient pas : ${JSON.stringify(urlsDemandees)}`);
    console.log(`[alertes] une alerte se cherche par son titre, le jeton de sa règle et sa source imputée (jamais par sa technique, qui a sa facette) ; la recherche se compose avec la portée, le filtre d'affichage et les facettes sans jamais partir au démon, met le groupement de côté et le rend au vidage, dit combien de lignes sur combien et CE QU'ELLE COUVRE, et la barre ne promet plus d'acquittement qui la dépasse`);
  } finally {
    poserLaRechercheDesAlertes("");
    document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine;
    S.alertGroupBy = etatOrigine.g; S.alertGroupAll = etatOrigine.a; S.alertUncased = etatOrigine.u; S.AUTH = etatOrigine.auth;
  }
}


// ---------------------------------------------------------------------------------------------
// 28. LA SÉLECTION REND CE QUI EST SÉLECTIONNÉ, ET UNE VALEUR TRANSPORTÉE A UN GESTE (`P11.4-h`).
//     (a) LE CLIC SE RETIRE DEVANT UNE SÉLECTION — mais SEULEMENT devant une vraie : un clic simple
//         (sélection vide), une sélection d'espaces, ou une sélection faite AILLEURS dans la page
//         laissent le geste passer. Sans ces trois-là, le remède remplacerait un défaut par une
//         interface morte, ce qui serait pire.
//     (b) LE GESTE DE COPIE EST UN, ET IL AVOUE SON ÉCHEC. Un presse-papier refusé (contexte non
//         sécurisé, permission) ne doit pas laisser le bouton reprendre son mot comme si la valeur y
//         était : c'est ainsi qu'on recopie à la main une valeur qu'on croit copiée.
//     (c) IL N'Y A PLUS QU'UN SEUL ÉCRIVAIN DU PRESSE-PAPIER dans `web/` — la propriété est DÉRIVÉE de
//         l'arbre, pas énumérée : tout module qui rappellerait `navigator.clipboard` en direct rougirait.
//     (d) LES DEUX GESTIONNAIRES MESURÉS passent par le mécanisme partagé (la ligne d'un tableau de
//         résultats, le titre d'une alerte) : la propriété est lue dans le SOURCE, parce que c'est le
//         CÂBLAGE qui était le défaut.
// ---------------------------------------------------------------------------------------------
{
  const cs = await import(pathToFileURL(path.join(WEB, "copie_et_selection.js")).href);
  // (a) le clic, sous chaque forme de sélection. Le shim n'a pas de `getSelection` : on l'installe le
  //     temps du témoin, ce qui est aussi la seule façon d'exercer les trois précautions.
  const hote = new Element("div"), dedans = new Element("span"), ailleurs = new Element("span");
  hote.appendChild(dedans);
  const selectionDeTest = { valeur: "", collapsed: true, ancre: null };
  const selOrigine = globalThis.window.getSelection;
  globalThis.window.getSelection = () => ({
    isCollapsed: selectionDeTest.collapsed,
    anchorNode: selectionDeTest.ancre,
    toString: () => selectionDeTest.valeur,
  });
  try {
    let passages = 0;
    cs.clicQuiRespecteLaSelection(hote, () => { passages += 1; });
    const cliquer = () => hote.onclick({});
    selectionDeTest.collapsed = true; selectionDeTest.valeur = ""; selectionDeTest.ancre = dedans;
    cliquer();
    exiger(passages === 1, "(28a) un clic SIMPLE (sélection vide) est avalé : le remède a tué le geste au lieu de le rendre");
    selectionDeTest.collapsed = false; selectionDeTest.valeur = "   "; selectionDeTest.ancre = dedans;
    cliquer();
    exiger(passages === 2, "(28a) une sélection réduite à des espaces suffit à annuler le geste");
    selectionDeTest.collapsed = false; selectionDeTest.valeur = "203.0.113.7"; selectionDeTest.ancre = ailleurs;
    cliquer();
    exiger(passages === 3, "(28a) une sélection faite AILLEURS dans la page gèle ce clic-là");
    selectionDeTest.collapsed = false; selectionDeTest.valeur = "203.0.113.7"; selectionDeTest.ancre = dedans;
    cliquer();
    exiger(passages === 3, "(28a) une sélection faite DANS l'élément ne retient pas le clic : le geste emporte encore la sélection avec la vue");
    exiger(cs.selectionEnCours(hote) === true && cs.selectionEnCours(ailleurs) === false, "(28a) le prédicat de sélection ne distingue pas l'hôte de ce qui lui est étranger");
  } finally {
    globalThis.window.getSelection = selOrigine;
  }
  // (b) le geste de copie : accusé au succès, aveu à l'échec, valeur lue AU CLIC (une valeur recomposée
  //     n'a pas à être figée à la construction).
  {
    const clipOrigine = globalThis.navigator.clipboard, execOrigine = document.execCommand;
    let ecrit = null;
    globalThis.navigator.clipboard = { writeText: async (v) => { ecrit = v; } };
    document.execCommand = () => false;
    try {
      let n = 0;
      const b = cs.boutonDeCopie(() => "valeur-" + (++n), { titre: "Copier ceci" });
      exiger(b.className === "copybtn", `(28b) le bouton de copie ne porte pas la classe partagée : « ${b.className} »`);
      exiger(/Copier/.test(b.textContent), `(28b) le bouton de copie ne dit pas ce qu'il fait : « ${b.textContent} »`);
      exiger(b.getAttribute("aria-label") === "Copier ceci", `(28b) le bouton de copie n'est pas nommé pour une aide technique : « ${b.getAttribute("aria-label")} »`);
      await b.onclick({});
      exiger(ecrit === "valeur-1", `(28b) la valeur n'est pas lue AU CLIC : « ${ecrit} »`);
      exiger(/Copié/.test(b.textContent), `(28b) le geste ne rend aucun accusé : « ${b.textContent} »`);
      // presse-papier REFUSÉ (contexte non sécurisé) et repli indisponible : l'échec se dit.
      globalThis.navigator.clipboard = { writeText: async () => { throw new Error("refusé"); } };
      const b2 = cs.boutonDeCopie("secret", {});
      await b2.onclick({});
      exiger(!/Copié/.test(b2.textContent), `(28b) un presse-papier REFUSÉ laisse le bouton dire « Copié » : la valeur serait recopiée à la main en croyant l'avoir — « ${b2.textContent} »`);
      // une valeur transportée : le texte reste sélectionnable au fragment, et son geste l'accompagne.
      const frag = cs.valeurTransportee("docs/DR-plume-restore.md");
      const code = frag.children.find((c) => c.tagName === "CODE");
      const bouton = frag.children.find((c) => c.tagName === "BUTTON");
      exiger(!!code && code.textContent === "docs/DR-plume-restore.md", `(28b) la valeur transportée ne rend pas son texte : ${JSON.stringify(frag.children.map((c) => c.tagName))}`);
      exiger(!!code && code.classList.contains("copyval"), "(28b) la valeur transportée ne prend pas le chrome partagé");
      exiger(!!bouton && bouton.classList.contains("copybtn"), "(28b) une valeur transportée n'offre AUCUN geste de copie");
    } finally {
      globalThis.navigator.clipboard = clipOrigine; document.execCommand = execOrigine;
    }
  }
  // (c)(d) l'arbre : un seul écrivain du presse-papier, et les deux gestionnaires mesurés y passent.
  {
    const fichiers = readdirSync(WEB).filter((f) => f.endsWith(".js"));
    const ecrivains = fichiers.filter((f) => /navigator\.clipboard/.test(readFileSync(path.join(WEB, f), "utf8")));
    exiger(ecrivains.length === 1 && ecrivains[0] === "copie_et_selection.js", `(28c) le presse-papier est écrit depuis ${ecrivains.length} module(s) au lieu du seul geste partagé : ${ecrivains.join(", ")}`);
    const viz = readFileSync(path.join(WEB, "viz.js"), "utf8"), alertesSrc = readFileSync(path.join(WEB, "alerts.js"), "utf8");
    exiger(/clicQuiRespecteLaSelection\(tr,/.test(viz), "(28d) la ligne du tableau de résultats ne passe plus par le clic qui respecte la sélection");
    exiger(!/\btr\.onclick\s*=/.test(viz), "(28d) une ligne de tableau pose encore un `onclick` en direct : elle avalerait de nouveau la sélection");
    exiger(/clicQuiRespecteLaSelection\(el,/.test(alertesSrc), "(28d) le titre d'une alerte ne passe plus par le clic qui respecte la sélection");
    exiger(!/'\.alertdrill'\)\.forEach\(el => el\.onclick =/.test(alertesSrc), "(28d) le titre d'une alerte pose encore un `onclick` en direct");
  }
  console.log(`[copie] le clic se retire devant une sélection faite dans l'élément, et devant elle seule (clic simple, espaces, sélection étrangère : le geste passe) ; le geste de copie est unique, lit sa valeur au clic, accuse le succès et AVOUE un presse-papier refusé ; un seul module de web/ écrit dans le presse-papier, et les deux gestionnaires mesurés y passent`);
}


// ---------------------------------------------------------------------------------------------
// 29. UN AVERTISSEMENT SE LIT EN ENTIER, ET LA RÉFÉRENCE QU'IL PORTE EST ATTEIGNABLE (`P11.4-g`).
//     MESURE (2026-08-23) : le texte servi par le démon était COMPLET dans le document ; c'est la
//     feuille de style qui le coupait — `.sys-comp-d` en `white-space:nowrap` + `overflow:hidden` +
//     `text-overflow:ellipsis`, sans même un `title` de repli. Le témoin juge donc les deux moitiés là
//     où elles vivent :
//       (a) LA FEUILLE — plus aucune troncature à une ligne sur le détail d'un composant, et la ligne
//           s'enroule pour l'accueillir ;
//       (b) LE RENDU — le détail est rendu ENTIER (dernier mot compris) et la référence documentaire y
//           est une valeur qu'on copie en un geste. Elle n'est PAS un lien : le démon ne sert en
//           fichiers que le répertoire web, `docs/` est une surface de dépôt — un lien rendrait 404.
//       (c) LE MOTIF EST DÉRIVÉ : un détail SANS référence rend un texte nu (aucun bouton parasite), un
//           détail qui en cite DEUX en rend deux, et le texte autour est conservé au caractère près.
// ---------------------------------------------------------------------------------------------
{
  const { componentRow, detailAvecSesReferences } = await import(pathToFileURL(path.join(WEB, "system.js")).href);
  const css = readFileSync(path.join(WEB, "style.css"), "utf8");
  const regle = (sel) => (css.match(new RegExp(`(^|\\n)${sel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\{([^}]*)\\}`)) || [])[2] || "";
  // (a) la feuille.
  const detailCss = regle(".sys-comp-d"), ligneCss = regle(".sys-comp");
  exiger(detailCss.length > 0 && ligneCss.length > 0, "(29a) instrument : les règles du composant sont introuvables dans style.css, le témoin jugerait du vide");
  exiger(!/text-overflow\s*:\s*ellipsis/.test(detailCss) && !/white-space\s*:\s*nowrap/.test(detailCss), `(29a) le détail d'un composant est encore coupé à une ligne : « ${detailCss} »`);
  exiger(/flex-wrap\s*:\s*wrap/.test(ligneCss), `(29a) la ligne d'un composant ne s'enroule pas : un détail long n'a nulle part où aller — « ${ligneCss} »`);
  // (b) le rendu, sur l'avertissement RÉEL que le démon publie quand aucun exercice n'a eu lieu.
  const avertissement = "AUCUN exercice de restauration enregistré — une sauvegarde jamais restaurée est une garantie non éprouvée (cf. docs/DR-plume-restore.md, `plume-restore-drill:`)";
  const ligne = componentRow({ component: "restore_drill", state: "yellow", detail: avertissement });
  const boite = ligne.children.find((c) => c.classList && c.classList.contains("sys-comp-d"));
  exiger(!!boite, "(29b) instrument : la boîte du détail n'est pas rendue");
  exiger(boite.textContent.startsWith("AUCUN exercice de restauration"), `(29b) le détail ne commence pas par l'avertissement servi : « ${boite.textContent} »`);
  exiger(/garantie non éprouvée/.test(boite.textContent), `(29b) la phrase s'arrête avant sa conclusion : « ${boite.textContent} »`);
  exiger(boite.textContent.includes("plume-restore-drill:"), `(29b) la FIN du texte servi n'atteint pas le document : « ${boite.textContent} »`);
  const bouton = (function trouver(el) { if (el.tagName === "BUTTON" && el.classList && el.classList.contains("copybtn")) return el; for (const c of el.children || []) { const t = trouver(c); if (t) return t; } return null; })(boite);
  exiger(!!bouton, "(29b) la référence documentaire n'a AUCUN geste : elle reste un chemin qu'on retape");
  const valeur = (function trouver(el) { if (el.classList && el.classList.contains("copyval")) return el; for (const c of el.children || []) { const t = trouver(c); if (t) return t; } return null; })(boite);
  exiger(!!valeur && valeur.textContent === "docs/DR-plume-restore.md", `(29b) la référence n'est pas isolée comme valeur transportée : « ${valeur && valeur.textContent} »`);
  // (c) le motif est dérivé : zéro, une, deux références — et le texte autour est conservé au caractère près.
  const nu = detailAvecSesReferences("dernière sauvegarde il y a 2 h");
  exiger(nu.length === 1 && nu[0].textContent === "dernière sauvegarde il y a 2 h", `(29c) un détail SANS référence n'est pas rendu tel quel : ${JSON.stringify(nu.map((n) => n.textContent))}`);
  const deux = detailAvecSesReferences("catégorie hors taxonomie (cf. docs/CIM.md) et fenêtre (cf. docs/PURGE.md).");
  const recolle = deux.map((n) => n.textContent).join("");
  exiger(recolle === "catégorie hors taxonomie (cf. docs/CIM.md) et fenêtre (cf. docs/PURGE.md).", `(29c) le texte autour des références n'est pas conservé au caractère près : « ${recolle} »`);
  const valeurs = deux.filter((n) => n.children && n.children.some((c) => c.classList && c.classList.contains("copyval")));
  exiger(valeurs.length === 2, `(29c) un détail qui cite DEUX documents n'en rend pas deux : ${valeurs.length}`);
  console.log(`[système] le détail d'un composant n'est plus coupé à une ligne par la feuille, la ligne s'enroule pour l'accueillir, l'avertissement d'exercice de restauration se lit jusqu'à sa conclusion, et la référence documentaire qu'il porte se copie en un geste — pas un lien, `+"`docs/`"+` n'est pas servi`);
}


// ---------------------------------------------------------------------------------------------
// 30. UN HÔTE MUET DIT S'IL EST NORMAL, ET LE COMPTE NE MÉLANGE PLUS (`P11.10-a`).
//     MESURE AVANT (2026-08-23, par lecture du code servi) : la charge utile de `/api/fleet` ne portait
//     AUCUN champ distinguant une machine décommissionnée, une machine de test et un agent tombé — les
//     trois rendaient `silent` — et l'en-tête additionnait des parts calculées sur les lignes AFFICHÉES
//     (bornées à 500) à côté d'un total calculé sur le parc ENTIER.
//       (a) LE DÉCLARANT EST NOMMÉ, colonne par colonne, sur la grammaire des sources (`P11.3-c`) : un
//           enrôlement, l'exploitant avec sa date et son motif, ou « personne n'a rien dit » — et ce
//           dernier n'est PAS présenté comme une déclaration.
//       (b) LES PARTS VIENNENT DU DÉMON et elles s'additionnent ; une charge utile SANS répartition le
//           DIT au lieu de recomposer un compte qui ne se retrouverait pas.
//       (c) UN SILENCE DÉCLARÉ ATTENDU N'EST PLUS PEINT COMME UNE ALARME, et une machine retirée porte
//           « hors parc » — le mot « muet » reste (c'est la même observation), la couleur d'alarme non.
//       (d) LE GESTE EST OFFERT SELON LE RÔLE : un lecteur ne se voit pas proposer une déclaration
//           qu'il ne peut pas poser, et la phrase de tête le lui dit autrement.
// ---------------------------------------------------------------------------------------------
{
  const { renderFleetInventory } = await import(pathToFileURL(path.join(WEB, "fleet.js")).href);
  const parc = {
    pipeline_fresh: true, now: 1_000_000, total: 5,
    repartition: { inventories: 5, flotte: 4, retires: 1, frais: 1, en_retard: 0, muet_attendu: 1, muet_inattendu: 2 },
    hosts: [
      { host: "srv-frais", status: "fresh", last_seen: 999_900, age_s: 100, first_seen: 1, signals: 10, enrolled: true, enroll_name: "agent-01", enroll_created: 500,
        attente: "signal_attendu", attente_libelle: "enrôlée sous le jeton « agent-01 » (ts 500)", declaree_par: "un enrôlement", alerte_si_muet: true, dans_la_flotte: true },
      { host: "srv-banc", status: "silent", last_seen: 900_000, age_s: 100_000, first_seen: 1, signals: 3, enrolled: false,
        attente: "silence_attendu", attente_libelle: "silence attendu, déclaré par eve (ts 900) — banc de test", attente_motif: "banc de test", declaree_par: "l'exploitant", alerte_si_muet: false, dans_la_flotte: true },
      { host: "srv-mort", status: "silent", last_seen: 900_000, age_s: 100_000, first_seen: 1, signals: 7, enrolled: false,
        attente: "non_declare", attente_libelle: null, declaree_par: null, alerte_si_muet: true, dans_la_flotte: true },
      { host: "srv-mort2", status: "silent", last_seen: 900_000, age_s: 100_000, first_seen: 1, signals: 7, enrolled: false,
        attente: "non_declare", attente_libelle: null, declaree_par: null, alerte_si_muet: true, dans_la_flotte: true },
      { host: "srv-vieux", status: "silent", last_seen: 800_000, age_s: 200_000, first_seen: 1, signals: 1, enrolled: false,
        attente: "retire", attente_libelle: "retirée du parc par root (ts 950) — décommissionnée", declaree_par: "l'exploitant", alerte_si_muet: false, dans_la_flotte: false },
    ],
  };
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const rendre = (d, role) => {
    const avant = S.AUTH;
    S.AUTH = { user: "u", role };
    const w = document.createElement("div");
    try { renderFleetInventory(w, d); } finally { S.AUTH = avant; }
    return w;
  };
  const trouver = (el, pred) => { if (pred(el)) return el; for (const c of el.children || []) { const t = trouver(c, pred); if (t) return t; } return null; };
  const tous = (el, pred, out = []) => { if (pred(el)) out.push(el); for (const c of el.children || []) tous(c, pred, out); return out; };
  const cls = (el, c) => el.classList && el.classList.contains(c);

  const w = rendre(parc, "editor");
  const texte = w.textContent;
  // (a) le déclarant, nommé, et l'absence de déclaration dite comme telle.
  const pourquoi = tous(w, (e) => cls(e, "fleetwhy")).map((e) => e.textContent);
  exiger(pourquoi.length === 5, `(30a) instrument : ${pourquoi.length} colonnes d'attente au lieu de 5 — le témoin jugerait du vide`);
  exiger(pourquoi.some((t) => /agent-01/.test(t)), `(30a) l'enrôlement ne nomme pas le jeton qui déclare la machine : ${JSON.stringify(pourquoi)}`);
  exiger(pourquoi.some((t) => /eve/.test(t) && /banc de test/.test(t)), `(30a) le déclarant, sa date et son motif ne sont pas rendus : ${JSON.stringify(pourquoi)}`);
  exiger(pourquoi.filter((t) => /personne n'a rien dit/.test(t)).length === 2, `(30a) « personne n'a rien dit » n'est pas dit là où c'est le cas : ${JSON.stringify(pourquoi)}`);
  const badges = tous(w, (e) => cls(e, "fleetbadge-attente")).map((e) => e.textContent);
  exiger(badges.filter((t) => t === "l'exploitant").length === 2 && badges.includes("un enrôlement"), `(30a) le badge ne nomme pas le déclarant : ${JSON.stringify(badges)}`);

  // (b) les parts du démon, et elles font le tout.
  const somme = parc.repartition.frais + parc.repartition.en_retard + parc.repartition.muet_attendu + parc.repartition.muet_inattendu;
  exiger(somme === parc.repartition.flotte && parc.repartition.flotte + parc.repartition.retires === parc.repartition.inventories, "(30b) instrument : la fixture elle-même ne s'additionne pas");
  const tete = trouver(w, (e) => cls(e, "fleetsum"));
  exiger(!!tete, "(30b) l'en-tête de répartition n'est pas rendu");
  exiger(/4 hôte\(s\) dans le parc/.test(tete.innerHTML), `(30b) le dénominateur n'est pas celui du parc : « ${tete.innerHTML} »`);
  exiger(/2<\/b> muet\(s\)/.test(tete.innerHTML) && /1<\/b> muet\(s\) attendu\(s\)/.test(tete.innerHTML), `(30b) les muets qui alertent ne sont pas séparés de ceux qui n'alertent pas : « ${tete.innerHTML} »`);
  exiger(/1 retirée\(s\) du parc/.test(tete.innerHTML), `(30b) les machines retirées ne sont pas comptées à part : « ${tete.innerHTML} »`);
  // …et une charge utile SANS répartition l'avoue au lieu de recomposer un compte de page.
  const sansParts = rendre({ ...parc, repartition: undefined }, "editor");
  const teteSans = trouver(sansParts, (e) => cls(e, "fleetsum"));
  exiger(/répartition non publiée/.test(teteSans.textContent), `(30b) sans répartition, la console invente un compte : « ${teteSans.textContent}|${teteSans.innerHTML} »`);

  // (c) le silence déclaré n'est plus peint comme une alarme, et le retrait se voit sur la ligne.
  const alarmes = tous(w, (e) => e.tagName === "B" && cls(e, "bad") && e.textContent === "muet");
  exiger(alarmes.length === 2, `(30c) ${alarmes.length} machine(s) peintes en alarme au lieu des 2 qui alertent vraiment`);
  const calmes = tous(w, (e) => e.tagName === "B" && cls(e, "calm") && e.textContent === "muet");
  exiger(calmes.length === 2, `(30c) un silence déclaré attendu (ou une machine retirée) est encore peint comme un incident : ${calmes.length}`);
  exiger(!!trouver(w, (e) => cls(e, "fleetbadge-retire")), "(30c) une machine retirée ne porte aucune marque sur sa ligne");

  // (d) le geste est offert à l'éditeur, refusé au lecteur, et la phrase de tête change de conseil.
  exiger(tous(w, (e) => cls(e, "fleetdeclare")).length === 5, "(30d) le geste de déclaration n'est pas offert sur chaque ligne à un éditeur");
  exiger(/2 hôte\(s\) muet\(s\) que personne n'a déclarés/.test(texte), `(30d) la console ne dit pas ce qui reste à trancher : ${texte.slice(0, 400)}`);
  exiger(/Actions → « déclarer »/.test(texte), "(30d) l'éditeur n'est pas renvoyé vers l'issue");
  const lecteur = rendre(parc, "viewer");
  exiger(tous(lecteur, (e) => cls(e, "fleetdeclare")).length === 0, "(30d) un lecteur se voit offrir un geste que le démon lui refuse");
  exiger(/rôle éditeur ou administrateur/.test(lecteur.textContent), "(30d) le rôle manquant n'est pas nommé au lecteur");

  // TÉMOIN NÉGATIF : un parc sans machine muette non déclarée ne rend AUCUNE phrase « à trancher ».
  const sain = rendre({
    ...parc,
    repartition: { inventories: 1, flotte: 1, retires: 0, frais: 1, en_retard: 0, muet_attendu: 0, muet_inattendu: 0 },
    hosts: [parc.hosts[0]],
  }, "editor");
  exiger(!/que personne n'a déclarés/.test(sain.textContent), `(30) une phrase toujours rendue ne prouverait rien : « ${sain.textContent.slice(0, 200)} »`);
  console.log(`[flotte] un hôte muet DIT s'il est normal : le déclarant est nommé (un enrôlement, l'exploitant avec sa date et son motif) et « personne n'a rien dit » se dit comme tel ; les parts viennent du démon et s'additionnent (leur absence est avouée), un silence déclaré attendu n'est plus peint en alarme, une machine retirée porte « hors parc », et le geste de déclaration suit le rôle`);
}


// ---------------------------------------------------------------------------------------------
// 31. COMPOSER UN PANNEAU À PARTIR DE CE QUE LE PRODUIT PORTE DÉJÀ (`P11.13-a`).
//     MESURE AVANT (2026-08-23) : DEUX des quatre absences annoncées se sont retournées. Les modèles
//     livrés ET les requêtes enregistrées SONT offerts à qui compose une requête (le bouton « Modèles »
//     de la barre ouvre une palette qui liste les deux) ; et le transport vers un panneau existait de
//     bout en bout, indirect — la palette charge la requête dans la barre, la création d'un panneau
//     pré-remplit son champ avec ce texte. Ce qui manquait était de pouvoir CHOISIR dans l'inventaire
//     LÀ OÙ L'ON COMPOSE, et — vraiment absent, celui-là — de partir d'une RÈGLE.
//       (a) LES TROIS STOCKS SONT DANS UNE SEULE LISTE, chacun nommé par son origine.
//       (b) UN STOCK QU'ON N'A PAS PU LIRE EST NOMMÉ — sinon « aucune règle » et « je n'ai pas pu lire
//           les règles » se rendent pareil ; TÉMOIN NÉGATIF : trois stocks lus -> aucun aveu.
//       (c) LA RECHERCHE EST CELLE, PARTAGÉE, DU DÉPÔT : plusieurs mots, sans casse ni accents, sur le
//           nom ET sur le texte de la requête, avec le résumé qui dit combien sur combien.
//       (d) LA FENÊTRE EST LA MODALE PARTAGÉE (fente `body`), pas un quatrième calque maison — et elle
//           REFUSE de rendre un choix quand aucune ligne n'a été prise.
// ---------------------------------------------------------------------------------------------
{
  const { inventaireComposable, choisirDansLexistant, texteDUnChoix } = await import(pathToFileURL(path.join(WEB, "composer_depuis_lexistant.js")).href);
  const fetchOrigine = globalThis.fetch;
  const stocks = {
    "/api/soql/templates": { templates: [{ id: "ssh-failed", title: "Échecs SSH", keywords: ["ssh", "auth"], soql: "search source=sshd action=failure | stats count by src_ip" }] },
    "/api/saved-queries": { queries: [{ id: 4, name: "Ma chasse aux scans", soql: "search source=portscan | stats count by src_ip" }] },
    "/api/rules": { rules: [
      { id: 1, name: "Brute-force SSH", query: "search source=sshd action=failure | stats count", is_soql: true, mitre: "T1110", query_reutilisable: "search source=sshd action=failure" },
      { id: 2, name: "Règle brute", query: "SELECT COUNT(*) FROM event WHERE ts>=__FROM__", is_soql: false, mitre: "", query_reutilisable: "SELECT COUNT(*) FROM event WHERE ts>=__FROM__" },
      { id: 3, name: "Règle sans requête", query: "", is_soql: true, mitre: "", query_reutilisable: "" },
    ] },
  };
  const servir = (manquants = []) => async (url) => {
    const chemin = String(url).split("?")[0];
    if (manquants.some((m) => chemin.endsWith(m))) throw new Error("réseau coupé (témoin)");
    const j = stocks[chemin];
    if (!j) throw new Error("chemin non servi : " + chemin);
    return { ok: true, status: 200, text: async () => JSON.stringify(j), json: async () => j };
  };
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const derniereOverlay = () => document.body.children.filter((c) => c.classList && c.classList.contains("modal-ov")).pop();
  const cueillirTous = (el, pred, out = []) => { if (pred(el)) out.push(el); for (const c of el.children || []) cueillirTous(c, pred, out); return out; };
  try {
    // (a) les trois stocks, dans une seule liste, chacun nommé.
    globalThis.fetch = servir();
    const inv = await inventaireComposable();
    exiger(inv.absents.length === 0, `(31b) TÉMOIN NÉGATIF : trois stocks LUS et pourtant un aveu d'absence — ${JSON.stringify(inv.absents)}`);
    const origines = [...new Set(inv.items.map((i) => i.origine))].sort();
    exiger(JSON.stringify(origines) === JSON.stringify(["ma requête", "modèle livré", "règle de détection"]), `(31a) les trois stocks ne sont pas tous offerts : ${JSON.stringify(origines)}`);
    // une règle sans requête réutilisable n'est PAS offerte (elle ne composerait rien) ; les deux autres le sont.
    const regles = inv.items.filter((i) => i.origine === "règle de détection");
    exiger(regles.length === 2, `(31a) une règle sans requête réutilisable est offerte quand même : ${JSON.stringify(regles.map((r) => r.titre))}`);
    // LA REQUÊTE VIENT DU DÉMON, pas d'une recomposition locale : l'étage scalaire terminal a disparu.
    const bf = regles.find((r) => r.titre === "Brute-force SSH");
    exiger(bf.requete === "search source=sshd action=failure" && bf.is_soql === true, `(31a) la requête réutilisable d'une règle n'est pas celle que le démon dérive : « ${bf.requete} »`);
    // …et une règle en SQL brut garde sa NATURE déclarée et ses marqueurs de fenêtre intacts.
    const brute = regles.find((r) => r.titre === "Règle brute");
    exiger(brute.is_soql === false && /__FROM__/.test(brute.requete), `(31a) la règle brute perd sa nature ou ses marqueurs : ${JSON.stringify(brute)}`);

    // (b) un stock non lu est NOMMÉ, et les autres restent servis.
    globalThis.fetch = servir(["/api/rules"]);
    const partiel = await inventaireComposable();
    exiger(partiel.absents.includes("règle de détection"), `(31b) un stock illisible disparaît en silence : ${JSON.stringify(partiel.absents)}`);
    exiger(partiel.items.length === 2, `(31b) l'échec d'un stock prive des autres : ${partiel.items.length} entrée(s)`);

    // (c) la recherche partagée : plusieurs mots, sans casse ni accents, sur le nom ET sur la requête.
    const { filtrerParRecherche } = await import(pathToFileURL(path.join(WEB, "recherche_de_liste.js")).href);
    exiger(filtrerParRecherche(inv.items, "echecs ssh", texteDUnChoix).length === 1, "(31c) la recherche ne trouve pas « Échecs SSH » sans accent ni casse");
    exiger(filtrerParRecherche(inv.items, "portscan", texteDUnChoix).length === 1, "(31c) la recherche ne regarde pas le TEXTE de la requête");
    exiger(filtrerParRecherche(inv.items, "brute ssh", texteDUnChoix).length === 1, "(31c) plusieurs mots n'ont pas resserré (ET)");

    // (d) la fenêtre : modale PARTAGÉE, liste cherchable dedans, et rien rendu sans choix.
    globalThis.fetch = servir();
    const p = choisirDansLexistant();
    let resolu = false; p.then(() => { resolu = true; });
    await tick(); await tick();
    const ov = derniereOverlay();
    exiger(!!ov, "(31d) aucune fenêtre partagée posée — la liste est-elle repartie dans un calque maison ?");
    const form = ov.children[0].children[0];
    exiger(!!cueillirTous(form, (e) => e.classList && e.classList.contains("compo-choix"))[0], "(31d) la liste n'est pas dans la modale partagée");
    const champ = cueillirTous(form, (e) => e.tagName === "INPUT" && e.type === "search")[0];
    exiger(!!champ && champ.classList.contains("field"), "(31d) le champ de recherche ne prend pas le chrome partagé");
    const lignes = () => cueillirTous(form, (e) => e.classList && e.classList.contains("compo-ligne"));
    exiger(lignes().length === 4, `(31d) ${lignes().length} ligne(s) offertes au lieu des 4 définitions réutilisables`);
    // AUCUNE LIGNE PRISE -> la validation REFUSE : la fenêtre ne se ferme pas et ne rend rien. (Le texte
    // du refus vit dans `.modal-err`, posé par `innerHTML` que le shim ne parse pas ; ce qui est jugeable
    // ici, et qui est le comportement, c'est que la promesse RESTE en attente.)
    form.onsubmit({ preventDefault() {} });
    await tick(); await tick();
    exiger(!resolu, "(31d) la fenêtre rend un choix alors qu'aucune définition n'a été prise");
    // une ligne prise, puis validée -> c'est CELLE-LÀ qui revient.
    const cible = lignes().find((b) => b.textContent.includes("Brute-force SSH"));
    cible.onclick();
    form.onsubmit({ preventDefault() {} });
    const choix = await p;
    exiger(choix && choix.titre === "Brute-force SSH" && choix.requete === "search source=sshd action=failure", `(31d) le choix rendu n'est pas celui qui a été pris : ${JSON.stringify(choix)}`);
    // …et une fenêtre ABANDONNÉE ne rend rien.
    const p2 = choisirDansLexistant();
    await tick(); await tick();
    const ov2 = derniereOverlay(); ov2.onclick({ target: ov2 });
    exiger((await p2) === null, "(31d) une fenêtre abandonnée rend quand même un choix");
  } finally {
    globalThis.fetch = fetchOrigine;
    document.body.children.filter((c) => c.classList && c.classList.contains("modal-ov")).forEach((c) => c.remove());
  }
  console.log(`[composer] un panneau part de ce que le produit porte DÉJÀ : les modèles livrés, les requêtes enregistrées et les requêtes de règles dans UNE liste, chacune nommée par son origine ; la requête d'une règle est celle que le DÉMON dérive (étage scalaire retiré, SQL brut intact avec ses marqueurs) ; un stock illisible est NOMMÉ au lieu de passer pour vide ; la recherche est celle, partagée, du dépôt ; et la fenêtre est la modale partagée, qui refuse un choix vide`);
}


// ---------------------------------------------------------------------------------------------
// 32. UN CONTRÔLE D'ÉCRITURE REFUSÉ AU LECTEUR RESTE, INERTE, AVEC SA RAISON (`P11.4-l`).
//     CE QU'AUCUN INSTRUMENT DU DÉPÔT NE SAVAIT VOIR. Deux contrôles refusés au même lecteur, VOISINS dans
//     la même ligne d'écran, suivaient des grammaires opposées : l'interrupteur restait visible, inerte et
//     motivé, pendant que les boutons d'écriture étaient EFFACÉS par la feuille (`display:none`), sans un
//     mot. Le harnais est un shim sans moteur de rendu : une règle qui masque n'existait donc pour personne,
//     et un bouton construit inerte AVEC sa raison pouvait être effacé juste après sans que rien ne rougisse.
//     Ce qu'un shim SAIT faire, en revanche, c'est LIRE la feuille et confronter ce qu'elle efface à ce que
//     la console rend — c'est le geste du témoin 3, qui dérive de `style.css` la notion de « classe dessinée ».
//
//     (a) LA FEUILLE N'EFFACE AUCUNE CLASSE QUE LA CONSOLE POSE SUR UN BOUTON. Dérivé des deux côtés, rien
//         d'énuméré : d'un côté les classes qu'une règle de rôle efface À ELLE SEULE (sélecteur = la portée
//         de rôle + UN composant, corps qui déclare `display:none`) ; de l'autre les classes que portent les
//         boutons du gabarit ET ceux que les fabriques partagées construisent. L'intersection doit être vide.
//         PORTÉE DE CE VOLET : sélecteur à DEUX composants seulement. Les règles à CONTEXTE et celles qui
//         visent un IDENTIFIANT sont jugées par (d), sur les contrôles que la console rend.
//     (b) LA RAISON EST ÉCRITE, ET C'EST LE CODE QUI L'ÉCRIT. Sur la ligne d'une règle rendue à un LECTEUR,
//         chaque bouton d'écriture porte la marque accessible du refus et une infobulle qui NOMME le rôle
//         qui manque. Témoin inverse : pour un ADMINISTRATEUR, les mêmes boutons ne portent ni l'une ni
//         l'autre — une version qui marquerait TOUJOURS ne passerait pas les deux.
//     (c) L'INERTIE EXISTE, ET ELLE PARLE. Le capteur de clic en phase de capture posé par le rôle rend le
//         geste inerte (il l'empêche et coupe la propagation AVANT tout gestionnaire de module), et il pose
//         la raison sur un bouton qu'aucune fabrique n'a construit — la cible du clic étant l'ICÔNE, pas le
//         bouton. Témoin inverse : sous un rôle administrateur, le même clic n'est ni empêché ni arrêté.
//     (d) UN EFFACEMENT NE SE DÉDUIT PLUS D'UN PARENT (`P11.4-m`). La règle qui a produit ce constat ne
//         nommait aucun bouton : elle visait un CONTENEUR d'outils, donc tout ce qu'on y pose ensuite —
//         l'étoile de favori, les rafraîchissements, les exports, l'ouverture dans l'éditeur, effacés au
//         motif du voisinage. (a) ne pouvait pas la voir. Ce volet lit la feuille en CHAÎNE COMPLÈTE (portée
//         de rôle, contextes, cible), construit la tuile et son panneau par le module lui-même, et exige que
//         RIEN de ce que la console rend ne soit effacé par un rôle sans porter la marque d'écriture. Deux
//         validations de l'instrument, sur des règles réelles et non écrites ici : chaque règle de la feuille,
//         jouée sur une chaîne fabriquée pour la satisfaire, doit être VUE ; et pour CHAQUE contrôle permis,
//         la règle de conteneur qui l'effaçait — dérivée de l'arbre rendu — doit être vue elle aussi. C'est
//         la preuve que réintroduire l'effacement ferait rougir, contrôle par contrôle.
//     (e) LA BORNE EST CELLE DU DÉMON, RELUE DANS SA TABLE. `route_min_role`, `is_readonly_post` et
//         `role_satisfies` sont RE-DÉRIVÉS de la source Rust — jamais recopiés ici. Chaque contrôle est
//         déclenché deux fois : sous un ÉDITEUR pour voir la route qu'il PORTE, sous un LECTEUR pour voir ce
//         que la console ENVOIE. Un contrôle dont toutes les routes portées sont ouvertes au lecteur n'est ni
//         marqué ni effacé. Témoin inverse : un contrôle qui porte une route REFUSÉE est ou bien traité comme
//         refusé (marque, raison posable, capteur partagé qui le reconnaît), ou bien n'envoie rien quand c'est
//         un lecteur qui agit — le geste MIXTE, dont l'effet local est permis et la persistance non.
// ---------------------------------------------------------------------------------------------
{
  const { applyRoleClass, motiverLeRefusAuLecteur, controleDEcritureSous } = await import(pathToFileURL(path.join(WEB, "core.js")).href);
  const { ruleRow } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const roleOrigine = S.AUTH;
  const regle = { id: 3, name: "SSH brute force", enabled: 1, query: "search source=sshd failed | stats count", is_soql: 1, op: ">", threshold: 10, severity: 3, interval_s: 300, window_s: 600, last_run: 0, last_value: null, last_fired: null, mitre: "T1110", managed: 2, compliance: "", risk_score: 0 };
  try {
    // (a) — CE QUE LA FEUILLE EFFACE POUR UN RÔLE, contre CE QUE LA CONSOLE POSE SUR UN BOUTON.
    const css = readFileSync(path.join(WEB, "style.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, " ");
    const html = readFileSync(path.join(WEB, "index.html"), "utf8");
    const effaceesParRole = new Set();
    for (const [, preludes, corps] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      if (!/display\s*:\s*none/.test(corps)) continue;
      for (const sel of preludes.split(",")) {
        const comp = sel.trim().replace(/>/g, " ").split(/\s+/).filter(Boolean);
        if (comp.length !== 2 || !/^body[.:]/.test(comp[0]) || !/role-/.test(comp[0])) continue;
        const m = /^\.([\w-]+)$/.exec(comp[1]);
        if (m) effaceesParRole.add(m[1]);
      }
    }
    const classesDeBoutons = new Set();
    for (const [, attrs] of html.matchAll(/<button\b([^>]*)>/g)) {
      const c = /class="([^"]*)"/.exec(attrs);
      if (c) c[1].split(/\s+/).filter(Boolean).forEach((x) => classesDeBoutons.add(x));
    }
    S.AUTH = { user: "bob", role: "viewer" };
    cueillir(ruleRow(regle), (e) => e.tagName === "BUTTON", []).forEach((b) => b.className.split(/\s+/).filter(Boolean).forEach((x) => classesDeBoutons.add(x)));
    exiger(effaceesParRole.size >= 1, "(32a) aucune règle de rôle n'efface plus rien : l'instrument ne peut plus rien mesurer, il refuse de conclure vert");
    exiger(classesDeBoutons.size >= 5, `(32a) seulement ${classesDeBoutons.size} classe(s) de bouton dérivée(s) du gabarit et des fabriques : la dérivation est cassée`);
    const effacesEtRendus = [...classesDeBoutons].filter((c) => effaceesParRole.has(c)).sort();
    exiger(effacesEtRendus.length === 0, `(32a) la feuille EFFACE pour un rôle des classes que la console pose sur un bouton : ${effacesEtRendus.join(", ")} — un contrôle refusé disparaît sans un mot au lieu de dire pourquoi`);

    // (b) — LA RAISON, POSÉE PAR LE CODE, SUR CE QUE LA FABRIQUE PARTAGÉE CONSTRUIT.
    const ecriture = (ligne) => cueillir(ligne, (e) => e.tagName === "BUTTON" && e.classList.contains("crud-btn"), []);
    const lecteur = ecriture(ruleRow(regle));
    exiger(lecteur.length >= 2, `(32b) la ligne d'une règle ne rend que ${lecteur.length} bouton(s) d'écriture : la mesure porterait sur rien`);
    for (const b of lecteur) {
      exiger(b.getAttribute("aria-disabled") === "true", `(32b) bouton d'écriture rendu à un LECTEUR sans la marque du refus : « ${b.textContent} » / ${JSON.stringify(b.className)}`);
      exiger(/rôle éditeur/.test(b.title || ""), `(32b) bouton d'écriture refusé à un lecteur dont l'infobulle ne NOMME pas le rôle qui manque : « ${b.title} »`);
    }
    S.AUTH = { user: "root", role: "admin" };
    const admin = ecriture(ruleRow(regle));
    exiger(admin.length === lecteur.length, `(32b) témoin inverse : ${admin.length} bouton(s) d'écriture pour un administrateur contre ${lecteur.length} pour un lecteur — le refus RETIRE encore des gestes`);
    for (const b of admin) {
      exiger(b.getAttribute("aria-disabled") === null, `(32b) témoin inverse : un ADMINISTRATEUR reçoit un bouton marqué refusé — la marque ne lit pas le rôle`);
      exiger(!/rôle éditeur/.test(b.title || ""), `(32b) témoin inverse : un administrateur lit la raison d'un refus qui ne le concerne pas — « ${b.title} »`);
    }

    // (c) — L'INERTIE, ET CE QU'ELLE DIT. Le capteur est celui que la pose du rôle câble sur le document.
    S.AUTH = { user: "bob", role: "viewer" };
    applyRoleClass("viewer");
    const capteur = ecouteursDuDocument.filter((e) => e.type === "click" && e.capture === true).pop();
    exiger(!!capteur, "(32c) la pose du rôle lecteur ne câble AUCUN capteur de clic en phase de capture : un bouton qu'aucune fabrique ne construit resterait actif");
    if (capteur) {
      const nu = new Element("button"); nu.className = "crud-btn"; nu.title = "Supprimer";
      const icone = new Element("svg"); nu.appendChild(icone);
      let empeche = 0, arrete = 0;
      capteur.rappel({ target: icone, preventDefault() { empeche++; }, stopPropagation() { arrete++; } });
      exiger(empeche === 1 && arrete === 1, `(32c) le clic d'un lecteur sur un geste d'écriture n'est pas rendu inerte (empêché ${empeche}, arrêté ${arrete}) : le gestionnaire du module partirait`);
      exiger(nu.getAttribute("aria-disabled") === "true" && /rôle éditeur/.test(nu.title), `(32c) le capteur rend le geste inerte SANS dire pourquoi — « ${nu.title} »`);
      exiger(/Supprimer/.test(nu.title), `(32c) la raison du refus a EFFACÉ l'infobulle que le bouton portait déjà — « ${nu.title} »`);
      S.AUTH = { user: "root", role: "admin" };
      const nuAdmin = new Element("button"); nuAdmin.className = "crud-btn";
      let empecheAdmin = 0, arreteAdmin = 0;
      capteur.rappel({ target: nuAdmin, preventDefault() { empecheAdmin++; }, stopPropagation() { arreteAdmin++; } });
      exiger(empecheAdmin === 0 && arreteAdmin === 0, `(32c) témoin inverse : le clic d'un ADMINISTRATEUR est rendu inerte (empêché ${empecheAdmin}, arrêté ${arreteAdmin}) — le capteur ne lit pas le rôle`);
      exiger(nuAdmin.getAttribute("aria-disabled") === null, "(32c) témoin inverse : un administrateur voit son bouton marqué refusé");
      exiger(motiverLeRefusAuLecteur(nuAdmin) === false, "(32c) témoin inverse : la pose du refus rend vrai sous un rôle administrateur");
    }

    // ===========================================================================================
    // (d) + (e) `P11.4-m` — LE REFUS NE SE DÉDUIT PLUS D'UN PARENT, ET LA BORNE EST CELLE DU DÉMON.
    // ===========================================================================================
    // LECTURE DE LA FEUILLE, CHAÎNE COMPLÈTE. (a) ne juge qu'un sélecteur à DEUX composants et écrivait sa
    // limite : une règle qui n'efface une classe QUE dans un contexte n'était jugée par personne. C'est
    // exactement la forme qui a produit ce constat. Ici la chaîne entière est modélisée (portée de rôle,
    // contextes, cible), et une règle qu'on ne saurait pas modéliser est COMPTÉE, jamais ignorée en silence.
    const composant = (txt) => {
      const c = { tag: null, id: null, classes: [], sans: [], modelise: true };
      const reste = txt.replace(/:not\(\s*\.([\w-]+)\s*\)/g, (_, x) => { c.sans.push(x); return ""; });
      if (!/^([a-zA-Z][\w-]*)?((?:[.#][\w-]+)*)$/.test(reste)) { c.modelise = false; return c; }
      const t = /^([a-zA-Z][\w-]*)/.exec(reste);
      if (t) c.tag = t[1].toUpperCase();
      for (const m of reste.matchAll(/([.#])([\w-]+)/g)) { if (m[1] === ".") c.classes.push(m[2]); else c.id = m[2]; }
      return c;
    };
    const porte = (el, c) => {
      if (!c.modelise || !el || !el.classList) return false;
      if (c.tag && el.tagName !== c.tag) return false;
      if (c.id && (el.id || (el.getAttribute && el.getAttribute("id")) || null) !== c.id) return false;
      if (c.classes.some((x) => !el.classList.contains(x))) return false;
      if (c.sans.some((x) => el.classList.contains(x))) return false;
      return true;
    };
    const reglesQuiEffacent = (feuille) => {
      const out = [];
      for (const m of feuille.replace(/\/\*[\s\S]*?\*\//g, " ").matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        if (!/display\s*:\s*none/.test(m[2])) continue;
        for (const sel of m[1].split(",")) {
          const comps = sel.trim().replace(/\s*>\s*/g, " ").split(/\s+/).filter(Boolean);
          if (comps.length < 2 || !/^body[.:]/.test(comps[0]) || !/role-/.test(comps[0])) continue;
          out.push({ selecteur: sel.trim(), portee: composant(comps[0]), chaine: comps.slice(1).map(composant) });
        }
      }
      return out;
    };
    // Un descendant : la cible porte le dernier composant, et les contextes apparaissent DANS L'ORDRE parmi
    // les ancêtres. Rend la règle qui efface, ou null.
    const effacePar = (regles, corps, ancetres, el) => {
      for (const r of regles) {
        if (!porte(corps, r.portee)) continue;
        if (!porte(el, r.chaine[r.chaine.length - 1])) continue;
        let i = ancetres.length - 1, ok = true;
        for (let k = r.chaine.length - 2; k >= 0; k--) {
          while (i >= 0 && !porte(ancetres[i], r.chaine[k])) i--;
          if (i < 0) { ok = false; break; }
          i--;
        }
        if (ok) return r;
      }
      return null;
    };
    const feuille = readFileSync(path.join(WEB, "style.css"), "utf8");
    const reglesRole = reglesQuiEffacent(feuille);
    const nonModelisees = reglesRole.filter((r) => !r.portee.modelise || !r.chaine.every((c) => c.modelise));
    exiger(reglesRole.length >= 1, "(32d) la feuille ne porte plus AUCUNE règle d'effacement de rôle : l'instrument ne mesure plus rien et refuse de conclure vert");
    exiger(nonModelisees.length === 0, `(32d) ${nonModelisees.length} règle(s) de rôle hors du modèle du témoin — il ne peut pas dire ce qu'elles effacent : ${nonModelisees.map((r) => r.selecteur).join(" | ")}`);
    // VALIDATION DE L'INSTRUMENT, SUR LES RÈGLES RÉELLES : chaque règle de la feuille, jouée sur une chaîne
    // fabriquée pour la satisfaire, DOIT être vue. Une version qui ne saurait rien voir ne passerait pas ici.
    for (const r of reglesRole) {
      const corpsF = new Element("body"); r.portee.classes.forEach((x) => corpsF.classList.add(x));
      const noeuds = r.chaine.map((c) => { const e = new Element(c.tag || "div"); if (c.id) e.id = c.id; c.classes.forEach((x) => e.classList.add(x)); return e; });
      exiger(!!effacePar([r], corpsF, noeuds.slice(0, -1), noeuds[noeuds.length - 1]), `(32d) le témoin ne sait pas voir sa propre règle « ${r.selecteur} » : instrument aveugle`);
    }

    // CE QUE LA CONSOLE REND VRAIMENT DANS UN CONTENEUR D'OUTILS. La tuile et ses panneaux sont construits
    // par le module, sous le rôle LECTEUR, avec un réseau simulé — c'est le seul moyen de voir les contrôles
    // qu'aucun gabarit ne déclare (ils naissent d'un `document.createElement`).
    const { renderDashboard } = await import(pathToFileURL(path.join(WEB, "dashboards.js")).href);
    const { flushPrefs } = await import(pathToFileURL(path.join(WEB, "prefs.js")).href);
    const appels = [];
    const fetchOrigine = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const u = String(url), meth = ((init && init.method) || "GET").toUpperCase();
      appels.push({ chemin: u.split("?")[0], methode: meth });
      const j = /\/api\/dashboard\/\d+$/.test(u.split("?")[0])
        ? { panels: [{ id: 11, title: "Connexions refusées", query: "search source=sshd failed | stats count", is_soql: 1, viz: "table", cols: 2, window_s: 0, visibility: "shared" }], editable: true }
        : { columns: ["c"], rows: [[1]], library_panels: [], templates: [], rules: [], saved: [] };
      return { ok: true, status: 200, text: async () => JSON.stringify(j) };
    };
    const tic = () => new Promise((r) => setTimeout(r, 0));
    const parcourir2 = (el, anc, acc) => {
      if (el.tagName === "BUTTON" || el.tagName === "SELECT") acc.push({ el, anc: anc.slice() });
      anc.push(el);
      (el.children || []).forEach((c) => { if (c && c.children) parcourir2(c, anc, acc); });
      anc.pop();
    };
    let controles = [];
    try {
      // Le shim n'a pas de moteur de sélecteurs : la grille rend `querySelectorAll` vide, et le
      // rafraîchissement d'un dashboard ne trouverait aucun panneau à recharger. On lui donne les panneaux
      // qu'elle vient elle-même de construire — l'arbre RENDU, pas une liste écrite ici.
      const batir = async (role) => {
        S.AUTH = { user: role === "viewer" ? "bob" : "eve", role };
        applyRoleClass(role);
        const t = renderDashboard({ id: 7, name: "Posture", panels: 1, cols: 2, visibility: "shared", editable: true, collapsed: false });
        for (let i = 0; i < 6; i++) await tic();
        const tous = []; parcourir2(t, [], tous);
        const grille = []; const cueillirGrille = (el) => { if (el.classList && el.classList.contains("dashgrid")) grille.push(el); (el.children || []).forEach((c) => c.children && cueillirGrille(c)); };
        cueillirGrille(t);
        const panneaux = []; const cueillirPanneaux = (el) => { if (el.classList && el.classList.contains("panel")) panneaux.push(el); (el.children || []).forEach((c) => c.children && cueillirPanneaux(c)); };
        cueillirPanneaux(t);
        grille.forEach((g) => { g.querySelectorAll = () => panneaux; });
        // Le shim n'a pas d'observateur d'intersection réel : aucun panneau ne devient jamais « visible », et
        // le rafraîchissement d'un dashboard ne rechargerait rien. On pose la visibilité que le navigateur
        // aurait posée — sans quoi ce geste-là échapperait à la mesure.
        panneaux.forEach((c) => { if (c._panel) { c._panel.loaded = true; c._panel.visible = true; } });
        return tous;
      };
      controles = await batir("viewer");
      const controlesEditeur = await batir("editor");
      exiger(controles.length >= 12, `(32d) la console ne rend que ${controles.length} contrôle(s) dans une tuile et ses panneaux : la mesure porterait sur presque rien`);
      exiger(controlesEditeur.length === controles.length && controlesEditeur.every((c, i) => c.el.className === controles[i].el.className),
        `(32e) la console ne rend pas la MÊME surface aux deux rôles (${controles.length} contrôles pour un lecteur, ${controlesEditeur.length} pour un éditeur) : le témoin ne peut plus apparier un geste à sa route`);
      S.AUTH = { user: "bob", role: "viewer" }; applyRoleClass("viewer");

      // (d) LE VERDICT — aucun contrôle rendu n'est effacé par un rôle sans porter la marque d'écriture.
      const effacesSansMarque = controles
        .map((c) => ({ ...c, regle: effacePar(reglesRole, document.body, c.anc, c.el) }))
        .filter((c) => c.regle && !c.el.classList.contains("crud-btn"));
      exiger(effacesSansMarque.length === 0, `(32d) ${effacesSansMarque.length} contrôle(s) que la console rend à un lecteur sont EFFACÉS par une règle de rôle sans porter la marque d'écriture : ${effacesSansMarque.map((c) => `« ${c.el.title || c.el.textContent} » (${c.el.className}) par « ${c.regle.selecteur} »`).join(" ; ")} — un effacement fondé sur l'appartenance à un parent ne distingue pas un geste REFUSÉ d'un geste PERMIS`);

      // LA MUTATION DE CETTE FAMILLE, JOUÉE PAR LE TÉMOIN LUI-MÊME. Pour CHAQUE contrôle sans marque, on
      // fabrique la règle de conteneur que la feuille portait — « portée de rôle, classe du parent, classe
      // du contrôle », dérivée de l'arbre RENDU et non écrite ici — et on exige qu'elle soit VUE. C'est la
      // preuve que réintroduire l'effacement ferait rougir (d), contrôle par contrôle.
      const sansMarque = controles.filter((c) => !c.el.classList.contains("crud-btn") && c.el.className && c.anc.some((a) => a.className));
      let vus = 0;
      for (const c of sansMarque) {
        const parent = [...c.anc].reverse().find((a) => a.className);
        const factice = reglesQuiEffacent(`body.role-viewer .${parent.className.split(/\s+/)[0]} .${c.el.className.split(/\s+/)[0]}{display:none!important}`);
        if (effacePar(factice, document.body, c.anc, c.el)) vus++;
      }
      exiger(sansMarque.length >= 7 && vus === sansMarque.length, `(32d) la règle de CONTENEUR n'est vue que sur ${vus} des ${sansMarque.length} contrôles permis : le témoin ne rougirait pas si l'effacement revenait`);

      // (e) LA BORNE EST CELLE DU DÉMON, LUE DANS SA TABLE — pas une borne recopiée ici. `route_min_role`
      // et `is_readonly_post` sont RE-DÉRIVÉS de la source Rust : une route déclarée ouverte au lecteur
      // (préférences self-service, lectures) ne peut pas porter la marque d'écriture, et une route bornée
      // à l'éditeur DOIT la porter. Le témoin ne conclut que sur les contrôles dont il a VU la route.
      const sansCommentaires = (s) => s.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/^[ \t]*\/\/.*$/gm, " ");
      const corpsDe = (src, signature) => {
        const i = src.indexOf(signature); if (i < 0) return null;
        const j = src.indexOf("{", i); let p = 0, k = j;
        for (; k < src.length; k++) { if (src[k] === "{") p++; else if (src[k] === "}") { p--; if (!p) break; } }
        return src.slice(j + 1, k);
      };
      const rbac = readFileSync(path.join(RACINE, "daemon", "src", "rbac.rs"), "utf8");
      const authRs = readFileSync(path.join(RACINE, "daemon", "src", "auth.rs"), "utf8");
      const litteraux = (txt) => {
        const p = [], vus2 = new Set();
        const prendre = (re, k) => { for (const m of txt.matchAll(re)) { p.push({ k, v: m[1] }); vus2.add(m[1]); } };
        prendre(/path\.starts_with\(\s*"([^"]*)"/g, "prefixe");
        prendre(/path\.ends_with\(\s*"([^"]*)"/g, "suffixe");
        prendre(/path\s*==\s*"([^"]*)"/g, "egal");
        for (const m of txt.matchAll(/"([^"]*)"/g)) if (!vus2.has(m[1])) p.push({ k: "egal", v: m[1] });
        return p;
      };
      // Un bloc dont la condition mêle `&&` n'est modélisé qu'en DISJONCTION : ne pas correspondre y reste
      // SÛR (aucun des membres n'est vrai), correspondre y devient INCERTAIN — et le témoin refuse alors de
      // conclure au lieu de deviner.
      const corpsTable = sansCommentaires((corpsDe(rbac, "fn route_min_role(") || "").replace(/#\[cfg\(feature[^\]]*\)\]\s*\{[\s\S]*?\n    \}/g, " "));
      const blocs = []; const reRet = /return\s+(?:if\s+mutating\s*\{\s*MinRole::(\w+)\s*\}\s*else\s*\{\s*MinRole::(\w+)\s*\}|MinRole::(\w+))\s*;/g;
      for (let m, debut = 0; (m = reRet.exec(corpsTable)); debut = reRet.lastIndex) {
        const cond = corpsTable.slice(debut, m.index);
        blocs.push({ preds: litteraux(cond), porte: /!\s*mutating/.test(cond) ? false : /\bmutating\b/.test(cond) ? true : null, approx: /&&/.test(cond), siMutant: m[1] || m[3], sinon: m[2] || m[3] });
      }
      const defautTable = (/MinRole::(\w+)\s*$/.exec(corpsTable.trim()) || [])[1] || null;
      exiger(blocs.length >= 8 && !!defautTable, `(32e) la table d'autorisation du démon n'a pas été relue (${blocs.length} bloc(s), défaut « ${defautTable} ») : le témoin refuse de conclure sur une table qu'il n'a pas lue`);
      const borne = (chemin, mutant) => {
        for (const b of blocs) {
          if (b.porte !== null && b.porte !== mutant) continue;
          const touche = b.preds.length === 0 || b.preds.some((p) => (p.k === "prefixe" ? chemin.startsWith(p.v) : p.k === "suffixe" ? chemin.endsWith(p.v) : chemin === p.v));
          if (!touche) continue;
          return { role: mutant ? b.siMutant : b.sinon, sur: !b.approx };
        }
        return { role: defautTable, sur: true };
      };
      const corpsRO = sansCommentaires(corpsDe(authRs, "fn is_readonly_post(") || "");
      const pairesRO = [...corpsRO.matchAll(/path\.starts_with\(\s*"([^"]*)"\s*\)\s*&&\s*path\.ends_with\(\s*"([^"]*)"\s*\)/g)].map((m) => [m[1], m[2]]);
      const egauxRO = new Set([...corpsRO.matchAll(/"([^"]*)"/g)].map((m) => m[1]));
      pairesRO.forEach(([a, b]) => { egauxRO.delete(a); egauxRO.delete(b); });
      const lectureSeulePost = (c) => egauxRO.has(c) || pairesRO.some(([a, b]) => c.startsWith(a) && c.endsWith(b));
      const corpsSat = sansCommentaires(corpsDe(rbac, "fn role_satisfies(") || "");
      const lecteurSatisfait = (nom) => { const m = new RegExp("MinRole::" + nom + "\\s*=>([^\\n]*)").exec(corpsSat); return m ? /"viewer"/.test(m[1]) : null; };
      exiger(egauxRO.size >= 4 && lecteurSatisfait("Read") === true && lecteurSatisfait("Write") === false && lecteurSatisfait("Admin") === false,
        `(32e) la relecture du démon ne dit pas ce qu'elle doit dire (POST de lecture : ${egauxRO.size} ; lecteur satisfait lecture=${lecteurSatisfait("Read")}, écriture=${lecteurSatisfait("Write")}, administration=${lecteurSatisfait("Admin")}) : instrument non validé`);
      const ouvertAuLecteur = (chemin, methode) => {
        const mutant = !["GET", "HEAD"].includes(methode) && !lectureSeulePost(chemin);
        const b = borne(chemin, mutant);
        return { mutant, role: b.role, sur: b.sur, ouvert: b.sur ? lecteurSatisfait(b.role) : null };
      };

      // ON DÉCLENCHE CHAQUE CONTRÔLE, ET ON REGARDE OÙ IL VA. Le geste est appelé DIRECTEMENT : le capteur de
      // refus de (c) est un AUTRE étage, et ce qu'on cherche ici est la ROUTE que le contrôle porte. Deux
      // états sont distingués et jamais confondus avec la conformité : un geste qui n'atteint aucune route
      // (export client, arrêt, impression), et un geste SUSPENDU sur une confirmation ou une saisie — celui-là
      // n'a pas encore atteint sa mutation, et le témoin le DIT au lieu de conclure.
      // DEUX PASSES, PARCE QUE LES DEUX QUESTIONS SONT DIFFÉRENTES : sous ÉDITEUR, quelle route le contrôle
      // PORTE ; sous LECTEUR, ce que la console ENVOIE vraiment. Un contrôle peut porter une route refusée et
      // ne rien envoyer — c'est le cas du geste MIXTE, dont l'effet local est permis et la persistance non.
      const modaleOuverte = () => document.body.children.some((e) => e.classList && e.classList.contains("modal-ov"));
      // Une préférence part APRÈS une temporisation ; on ne la force que si le contrôle a VRAIMENT écrit dans
      // le magasin (le miroir change), sinon chaque contrôle se verrait attribuer l'envoi du précédent.
      const miroirPrefs = () => { try { return localStorage.getItem("plume_prefs"); } catch (e) { return null; } };
      const sonder = async (liste) => {
        const vus = [];
        for (const c of liste) {
          document.body.children.filter((e) => e.classList && e.classList.contains("modal-ov")).forEach((e) => e.remove());
          appels.length = 0;
          const avantPrefs = miroirPrefs();
          try { if (typeof c.el.onchange === "function") { c.el.value = "4"; c.el.onchange({ target: c.el }); } else if (typeof c.el.onclick === "function") c.el.onclick({ target: c.el, stopPropagation() {}, preventDefault() {} }); } catch (e) { /* la route est ce qu'on cherche, pas le rendu */ }
          await tic();
          if (miroirPrefs() !== avantPrefs) { try { await flushPrefs(); } catch (e) {} }
          const routes = appels.map((a) => ({ ...a, ...ouvertAuLecteur(a.chemin, a.methode) })).filter((r) => r.sur);
          vus.push({ c, routes, suspendu: modaleOuverte() });
        }
        return vus;
      };
      const sousLecteur = await sonder(controles);
      // La MÊME surface, sous un rôle qui PEUT écrire : les gestes révèlent alors la route qu'ils portent.
      S.AUTH = { user: "eve", role: "editor" }; applyRoleClass("editor");
      const sousEditeur = await sonder(controlesEditeur);
      S.AUTH = { user: "bob", role: "viewer" }; applyRoleClass("viewer");

      const marque = (c) => c.el.classList.contains("crud-btn");
      const refuseeParmi = (v) => v.routes.some((r) => r.ouvert === false);
      // (e-a) LE VERDICT DE `P11.4-m` : un contrôle dont TOUTES les routes portées sont ouvertes au lecteur —
      // geste allé au bout — n'est ni marqué d'écriture, ni effacé par une règle de rôle.
      const permis = sousEditeur.filter((v) => !v.suspendu && v.routes.length && !refuseeParmi(v));
      const permisTraitesEnRefus = permis.filter((v) => marque(v.c) || effacePar(reglesRole, document.body, v.c.anc, v.c.el));
      // (e-b) TÉMOIN INVERSE : un contrôle qui PORTE une route refusée au lecteur ne peut pas être laissé
      // libre. De deux choses l'une, et le témoin accepte les deux : ou il est traité comme refusé (marque
      // portée, raison posable, capteur partagé qui le reconnaît), ou la console N'ENVOIE RIEN de refusé
      // quand c'est un lecteur qui agit. Tout le reste est un 403 muet.
      const porteurs = sousEditeur.map((v, i) => ({ v, envoi: sousLecteur[i] })).filter((x) => refuseeParmi(x.v));
      const porteursLibres = porteurs.filter(({ v, envoi }) => {
        const traiteEnRefus = marque(v.c) && motiverLeRefusAuLecteur(v.c.el) && controleDEcritureSous(v.c.el) === v.c.el;
        return !traiteEnRefus && refuseeParmi(envoi);
      });
      exiger(permis.length >= 2, `(32e) seuls ${permis.length} contrôle(s) ont mené leur geste au bout sur des routes toutes ouvertes : le témoin ne relie plus rien à la borne du démon`);
      exiger(porteurs.length >= 2, `(32e) seuls ${porteurs.length} contrôle(s) portent encore une route que le démon refuse à un lecteur : le témoin inverse ne mesure plus rien et refuse de conclure vert`);
      exiger(permisTraitesEnRefus.length === 0, `(32e) ${permisTraitesEnRefus.length} contrôle(s) sont traités en refus alors que le démon leur ouvre TOUTES les routes qu'ils portent : ${permisTraitesEnRefus.map((v) => `« ${v.c.el.title || v.c.el.textContent} » (${v.c.el.className}) -> ${v.routes.map((r) => r.methode + " " + r.chemin + " (" + r.role + ")").join(", ")}`).join(" ; ")}`);
      exiger(porteursLibres.length === 0, `(32e) témoin inverse : ${porteursLibres.length} contrôle(s) portent une route que le démon REFUSE à un lecteur, ne sont pas traités comme refusés, et l'envoient quand même : ${porteursLibres.map(({ v }) => `« ${v.c.el.title || v.c.el.textContent} » (${v.c.el.className}) -> ${v.routes.filter((r) => r.ouvert === false).map((r) => r.methode + " " + r.chemin + " (" + r.role + ")").join(", ")}`).join(" ; ")}`);
      console.log(`[refus-conteneur] ${controles.length} contrôles rendus dans une tuile et son panneau, identiques sous les deux rôles ; ${reglesRole.length} règles d'effacement de rôle, toutes modélisées et toutes VUES par le témoin : aucun contrôle effacé sans porter la marque d'écriture, et la règle de CONTENEUR qui les effaçait est vue sur les ${sansMarque.length} contrôles permis — elle rougirait donc contrôle par contrôle. Table d'autorisation du démon RELUE (${blocs.length} blocs, défaut ${defautTable}, ${egauxRO.size} POST de lecture) : ${permis.length} gestes menés au bout sur des routes TOUTES ouvertes au lecteur, aucun marqué ni effacé ; ${porteurs.length} qui portent une route refusée, tous traités comme refusés ou n'envoyant rien quand c'est un lecteur qui agit. HORS DU TÉMOIN, ÉCRIT : un geste SUSPENDU sur une confirmation ou une saisie (${sousEditeur.filter((v) => v.suspendu).length} ici) n'a pas atteint sa mutation et n'est pas jugé « permis » ; un contrôle qui n'appelle rien ne l'est pas non plus ; un bloc de la table dont la condition mêle des « et » n'est modélisé qu'en disjonction, et le témoin refuse alors de conclure ; le bloc gaté par une option de compilation absente du build par défaut n'est pas lu.`);
    } finally {
      globalThis.fetch = fetchOrigine;
    }

    console.log(`[refus] une seule grammaire pour les contrôles refusés : la feuille n'efface aucune des ${classesDeBoutons.size} classes de bouton dérivées du gabarit et des fabriques (${effaceesParRole.size} classe(s) effacée(s) par un rôle, aucune rendue), les ${lecteur.length} boutons d'écriture d'une règle rendue à un lecteur portent la marque du refus et NOMMENT le rôle qui manque, aucun pour un administrateur, et le capteur partagé rend inerte — en le disant — le clic d'un lecteur sur un bouton qu'aucune fabrique n'a construit`);
  } finally {
    S.AUTH = roleOrigine;
    document.body.classList.remove("role-viewer"); document.body.classList.remove("role-editor"); document.body.classList.remove("role-admin");
  }
}


// ---------------------------------------------------------------------------------------------
// 33. LA CONSOLE NE PORTE PAS UNE SECONDE COPIE DU CATALOGUE ATT&CK (`P11.6-c`).
//     Le catalogue vit d'un seul côté : `daemon/src/attack_names.rs`. La console garde un
//     SOUS-ENSEMBLE de libellés pour les deux panneaux dont les routes servent `mitre` NU (file
//     d'alertes, administration des règles) ; la matrice, elle, ne garde plus rien — son nom est servi.
//     Un sous-ensemble recopié à la main n'est pas un repli : c'est une source qui vieillit sans le
//     dire. Ce témoin lui retire ce silence. Il DÉRIVE du texte du démon le nom que celui-ci émettrait
//     pour chaque clé listée — la même règle de résolution, réécrite ici — et refuse l'écart DANS LES
//     DEUX SENS : un libellé qui s'écarte, une clé que le catalogue ne connaît pas. Il ne peut pas
//     rendre la table complète (elle nomme moins que le catalogue, et c'est écrit à côté d'elle) ;
//     il garantit qu'elle est INCOMPLÈTE et jamais FAUSSE.
//     L'INSTRUMENT EST VALIDÉ AVANT TOUT VERDICT : les tables lues non vides, la règle de résolution
//     éprouvée sur ses quatre cas (composition, parent seul, hors catalogue, hors format), et surtout
//     ce que le témoin a LU du texte de `core.js` confronté à ce que le module SERT — une lecture
//     désynchronisée garderait une valeur qui ne mesure rien.
//     Enfin il refuse une TROISIÈME copie : aucun autre module de `web/` ne pose de table `T####: "…"`.
// ---------------------------------------------------------------------------------------------
{
  const rs = readFileSync(path.join(RACINE, "daemon", "src", "attack_names.rs"), "utf8");
  const tableRust = (nom) => {
    const m = rs.match(new RegExp(`const ${nom}: &\\[\\(&str, &str\\)\\] = &\\[([\\s\\S]*?)\\n\\];`));
    exiger(!!m, `(33) table \`${nom}\` introuvable dans le catalogue du démon : le témoin ne lit plus rien`);
    const t = new Map();
    // rustfmt éclate une entrée longue sur plusieurs lignes : on replie les blancs avant de lire.
    if (m) for (const e of m[1].replace(/\s+/g, " ").matchAll(/\(\s*"(T\d{4}(?:\.\d{3})?)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)/g)) t.set(e[1], e[2]);
    return t;
  };
  const PARENTS = tableRust("TECHNIQUE_NAMES");
  const SOUS = tableRust("SUBTECHNIQUE_NAMES");

  // Règle de résolution du démon (`attack_names::technique_name`), DÉRIVÉE et non recopiée en données.
  const nomDuDemon = (tid) => {
    const t = String(tid == null ? "" : tid).trim().toUpperCase();
    const point = t.indexOf(".");
    const base = point < 0 ? t : t.slice(0, point);
    const sous = point < 0 ? "" : t.slice(point + 1);
    if (!/^T\d+$/.test(base)) return null;
    if (point >= 0 && !/^\d+$/.test(sous)) return null;
    const parent = PARENTS.get(base);
    if (parent === undefined) return null;
    if (!sous) return parent;
    const n = SOUS.get(t);
    return n === undefined ? `${parent} (sous-technique .${sous})` : `${parent}: ${n}`;
  };

  // — instrument : les tables sont lues, et la règle se comporte comme celle du démon sur ses 4 cas.
  exiger(PARENTS.size > 100 && SOUS.size > 0, `(33) catalogue lu vide ou tronqué (${PARENTS.size} technique(s) parente(s), ${SOUS.size} sous-technique(s)) : le témoin refuse de conclure`);
  exiger(nomDuDemon(" t1110.003 ") === "Brute Force: Password Spraying", `(33) composition parent+sous-technique non reproduite : « ${nomDuDemon(" t1110.003 ")} »`);
  exiger(nomDuDemon("T1110.999") === "Brute Force (sous-technique .999)", `(33) sous-technique inconnue : « ${nomDuDemon("T1110.999")} » au lieu du parent qui DIT le rang`);
  exiger(nomDuDemon("T9999") === null, "(33) un identifiant hors catalogue doit rendre null, pas un nom");
  exiger(nomDuDemon("pas-un-identifiant") === null, "(33) un jeton hors format doit rendre null");

  const srcCore = readFileSync(path.join(WEB, "core.js"), "utf8");
  const mTable = srcCore.match(/const MITRE_NAMES = \{([\s\S]*?)\};/);
  exiger(!!mTable, "(33) table `MITRE_NAMES` introuvable dans core.js : le témoin ne lit plus ce qu'il juge");
  const locale = new Map();
  if (mTable) for (const e of mTable[1].matchAll(/"?(T\d{4}(?:\.\d{3})?)"?\s*:\s*"((?:[^"\\]|\\.)*)"/g)) locale.set(e[1], e[2]);
  exiger(locale.size > 0, "(33) table locale lue vide : le témoin refuse de conclure sur une lecture qui ne rend rien");

  // — instrument : ce qui a été LU du texte est bien ce que le module SERT.
  const { mitreName } = await import(pathToFileURL(path.join(WEB, "core.js")).href);
  for (const [tid, nom] of locale) {
    exiger(mitreName(tid) === nom, `(33) lecture désynchronisée : le texte de core.js donne « ${nom} » pour ${tid}, le module sert « ${mitreName(tid)} »`);
  }

  // — le verdict, dans les deux sens.
  const ecarts = [];
  const inconnues = [];
  for (const [tid, nom] of locale) {
    const attendu = nomDuDemon(tid);
    if (attendu === null) inconnues.push(tid);
    else if (attendu !== nom) ecarts.push(`${tid} : console « ${nom} » ≠ démon « ${attendu} »`);
  }
  exiger(ecarts.length === 0, `(33) ${ecarts.length} libellé(s) de la console ont DIVERGÉ du catalogue du démon : ${ecarts.join(" ; ")} — deux porteurs du même savoir, donc deux vérités`);
  exiger(inconnues.length === 0, `(33) ${inconnues.length} clé(s) de la console que le catalogue du démon ne connaît pas : ${inconnues.join(", ")} — un libellé sans porteur est une source qui invente`);

  // — aucune troisième copie, et la matrice n'en reprend pas une.
  const autresPorteurs = modules.filter((f) => f !== "core.js")
    .filter((f) => /[{,]\s*"?T\d{4}(?:\.\d{3})?"?\s*:\s*"/.test(readFileSync(path.join(WEB, f), "utf8")));
  exiger(autresPorteurs.length === 0, `(33) ${autresPorteurs.length} autre(s) module(s) posent une table identifiant ATT&CK -> nom : ${autresPorteurs.join(", ")} — la console n'en porte qu'UNE, et c'est celle que ce témoin tient`);
  const srcAttack = readFileSync(path.join(WEB, "attack.js"), "utf8");
  exiger(!/\bmitreName\b/.test(srcAttack), "(33) `attack.js` reprend la table locale alors que sa route sert un nom pour chaque technique qu'elle rend : un second porteur y rouvrirait la divergence");

  console.log(`[attack-catalogue] catalogue du démon LU : ${PARENTS.size} techniques parentes, ${SOUS.size} sous-techniques nommées. La console en nomme ${locale.size}, toutes DÉRIVÉES : aucun écart, aucune clé hors catalogue, aucune autre table dans web/, et la matrice n'en porte plus (son nom est servi). Ce que ce témoin NE tient PAS, et qui est écrit à côté de la table : la COMPLÉTUDE — la console peut nommer moins que le démon, et le fera dès qu'une technique s'ajoutera ; seule une route dédiée servant le catalogue ferait disparaître ce sous-ensemble.`);
}

// ---------------------------------------------------------------------------------------------
// 34. LA FRONTIÈRE DE L'AIDE DIT CE QU'ELLE NE COUVRE PAS, ET ELLE NE PEUT PLUS DEVENIR FAUSSE EN
//     SILENCE (`P11.4-k`). L'extraction du registre (`P11.4-e`) a sorti les SECTIONS ; le sommaire, le
//     glossaire et les raccourcis sont restés du CONTENU dans le module de la mécanique, et les deux
//     gardes qui DÉRIVENT le porteur du registre ne regardent pas ce contenu-là : la frontière était donc
//     fausse à l'endroit où on la croyait tenue. Le déplacement, tenté et mesuré, est PUR et REFUSÉ par
//     deux gardes ; ce témoin tient l'autre issue — la frontière est ÉCRITE, et elle est DÉRIVÉE.
//     (a) La liste déclarée en tête du module et les tables de contenu que le module porte réellement sont
//         le MÊME ensemble, dans les deux sens : une table neuve non déclarée rougit, une déclaration
//         devenue fausse rougit.
//     (b) Le sommaire reste dans le fichier auquel la garde des déclencheurs d'aide est ANCRÉE PAR SON NOM.
//         Ce nom est LU dans la garde, jamais recopié ici. Déplacer le sommaire ferait sortir ses entrées
//         du compte des déclencheurs sans faire rougir cette garde-là : le silence est rendu bruyant ici.
//     L'instrument se valide avant de conclure : la lecture qui trouve zéro table, zéro nom déclaré, zéro
//     entrée de sommaire, ou qui ne retrouve pas l'ancre dans la garde, REFUSE de conclure.
// ---------------------------------------------------------------------------------------------
{
  const RE_TABLE = /^const ([A-Z][A-Z0-9_]*)\s*=\s*[[{]/gm;
  const RE_DECLARE = /^\/\/ CONTENU QUI RESTE ICI : (.+)$/m;
  const srcAide = readFileSync(path.join(WEB, "help.js"), "utf8");

  // (a) déclaré <-> porté, dans les deux sens.
  const portees = new Set([...srcAide.matchAll(RE_TABLE)].map((m) => m[1]));
  const ligne = srcAide.match(RE_DECLARE);
  exiger(!!ligne, "(34) le module de la mécanique de l'aide ne DÉCLARE plus ce qu'il garde : la ligne « CONTENU QUI RESTE ICI : » a disparu, et la frontière redevient une croyance");
  const declarees = new Set(ligne ? [...ligne[1].matchAll(/`([A-Z][A-Z0-9_]*)`/g)].map((m) => m[1]) : []);
  exiger(portees.size > 0 && declarees.size > 0, `(34) instrument : ${portees.size} table(s) lue(s), ${declarees.size} nom(s) déclaré(s) — la lecture est cassée, le témoin refuse de conclure`);
  const nonDeclarees = [...portees].filter((t) => !declarees.has(t)).sort();
  const declareesAbsentes = [...declarees].filter((t) => !portees.has(t)).sort();
  exiger(nonDeclarees.length === 0, `(34) ${nonDeclarees.length} table(s) de contenu que le module porte SANS les déclarer : ${nonDeclarees.join(", ")} — la frontière écrite ne dit plus ce qu'elle ne couvre pas`);
  exiger(declareesAbsentes.length === 0, `(34) ${declareesAbsentes.length} nom(s) déclaré(s) que le module ne porte plus : ${declareesAbsentes.join(", ")} — une déclaration périmée fait croire à une frontière qui n'existe plus`);

  // (b) LE SOMMAIRE N'EST PLUS ANCRÉ À UN NOM DE FICHIER (`P11.13-d`). Ce témoin disait, jusqu'au
  //     2026-08-26, « le sommaire DOIT rester dans le fichier auquel la garde est ancrée » : il rendait
  //     visible un refus au lieu de lever l'obstacle. L'obstacle est levé — la garde dérive la PORTÉE de
  //     `const HELP_INDEX = [ … ]` où qu'elle vive — et le témoin s'inverse : il interdit désormais le
  //     RETOUR à un nom de fichier, et vérifie que les deux outils nomment la MÊME propriété.
  const srcGarde = readFileSync(path.join(RACINE, ".github", "scripts", "check_every_help_trigger_has_a_section.py"), "utf8");
  const motifSommaire = srcGarde.match(/\(\s*re\.compile\([^)]*\bk:[^)]*\)\s*,\s*([^)]+?)\s*\)\s*,/);
  exiger(!!motifSommaire, "(34) instrument : le motif de sommaire de la garde des déclencheurs n'est plus retrouvé — son ancrage a changé de forme, et ce témoin ne mesure plus ce qu'il croit");
  const ancrage = motifSommaire ? motifSommaire[1].trim() : "";
  exiger(!/^["']/.test(ancrage),
    `(34) la garde des déclencheurs d'aide ancre de nouveau le motif du sommaire à un NOM DE FICHIER (${ancrage}) : un emplacement là où il faut une PROPRIÉTÉ. Déplacé, le sommaire sortirait du compte des déclencheurs et la garde resterait VERTE — mesuré le 2026-08-26 : 29 clés et 56 sites vus tombaient à 28 et 29, sans un mot.`);
  exiger(ancrage === "SOMMAIRE", `(34) instrument : l'ancrage du motif de sommaire est « ${ancrage} » et non la portée dérivée « SOMMAIRE » — ce témoin ne sait plus ce qu'il lit`);
  const defSommaire = srcGarde.match(/^RE_DEFINITION_DU_SOMMAIRE\s*=\s*re\.compile\(r"([^"]+)"\)/m);
  exiger(!!defSommaire && /HELP_INDEX/.test(defSommaire[1]),
    "(34) instrument : la garde ne dérive plus la portée du sommaire d'une définition `const HELP_INDEX = [` — le témoin et la garde ne nomment plus la même propriété");
  const porteursDuSommaire = modules.filter((f) => /^const HELP_INDEX\s*=\s*\[/m.test(readFileSync(path.join(WEB, f), "utf8")));
  exiger(porteursDuSommaire.length === 1, `(34) ${porteursDuSommaire.length} module(s) définissent le sommaire du guide (${porteursDuSommaire.join(", ") || "aucun"}) : un seul attendu, sinon la garde refuse de conclure et le compte des déclencheurs s'effondre`);
  const porteurDuSommaire = porteursDuSommaire[0];
  const entrees = porteurDuSommaire ? (readFileSync(path.join(WEB, porteurDuSommaire), "utf8").match(/\{\s*k:\s*['"]/g) || []).length : 0;
  exiger(entrees > 10, `(34) instrument : ${entrees} entrée(s) de sommaire lues — la lecture est cassée`);
  const cliquet = srcGarde.match(/^CLIQUET_SITES_DECLENCHEURS\s*=\s*(\d+)/m);
  exiger(!!cliquet && Number(cliquet[1]) >= entrees,
    `(34) la garde des déclencheurs ne garde plus le COMPTE qu'elle voit par un cliquet au moins égal aux ${entrees} entrées du sommaire (${cliquet ? cliquet[1] : "aucun cliquet"}) : une chute du nombre de déclencheurs vus rendrait la garde plus verte, en silence.`);

  console.log(`[frontiere-aide] ${portees.size} tables de contenu restent dans la mécanique (${[...portees].sort().join(", ")}), toutes DÉCLARÉES en tête du module et dérivées ici dans les deux sens ; le sommaire et ses ${entrees} entrées vivent dans « ${porteurDuSommaire} », et la garde des déclencheurs les trouve par la PORTÉE de leur définition, plus par un nom de fichier — le déplacement est devenu possible, et une chute du compte vu est tenue par un cliquet à ${cliquet && cliquet[1]} sites. Ce que ce témoin NE tient PAS : il lit du TEXTE dans la garde, il ne l'exécute pas ; c'est la garde elle-même qui prouve par ses témoins que la portée dérivée est lue.`);
}

// ---------------------------------------------------------------------------------------------
// 35. CE QUI PEINT UNE VUE EST DÉCLARÉ, ET LA CADENCE EN DÉRIVE SON PÉRIMÈTRE (`P11.17-a`,
//     `P11.17-d`, `P11.14-e`). Trois défauts de la même famille se ferment ensemble, et ce témoin
//     tient les trois — aucun ne pouvait être tenu avant que le shim porte l'arbre de la page.
//     (a) COUVERTURE : chaque `<section>` de `<main>` est peinte par au moins une charge DÉCLARÉE, ou
//         nommée dans la table des sections sans charge AVEC SA RAISON. L'attente vient d'index.html,
//         la réponse du registre : deux sources indépendantes. C'est la garde que `P11.14-e` demande —
//         une liste écrite à la main s'oublie, et quatre panneaux avaient été oubliés.
//     (b) AUCUN NOM D'ONGLET ne décide de quoi que ce soit dans le module qui porte le modèle. Les
//         identifiants sont DÉRIVÉS du modèle lui-même ; toute comparaison à l'un d'eux est refusée.
//         Le module est trouvé par ce qu'il DÉFINIT, jamais par son nom de fichier.
//     (c) PÉRIMÈTRE : sur chaque onglet, les charges rejouées à l'entrée sont exactement celles dont la
//         cible vit dans une section que cet onglet montre — et aucune charge ne vise une section
//         déclarée sans charge. C'est la propriété corrigée sous `P11.17-a`, enfin gardable.
//     (d) CHAQUE ONGLET peint quelque chose, ou toutes ses sections sont déclarées sans charge.
//     L'INSTRUMENT SE VALIDE : planchers de non-dégénérescence, puis quatre fautes INJECTÉES sur des
//     copies — un registre amputé, une charge visant une section déclarée sans charge, un arbre à plat
//     (le trou de `P11.13-e`), un onglet vidé de ses charges — que la dérivation DOIT voir.
// ---------------------------------------------------------------------------------------------
{
  const nav = await import(pathToFileURL(path.join(WEB, "navigation.js")).href);
  const { CHARGES_DE_LA_CONSOLE, SECTIONS_SANS_CHARGE, SPACES: MODELE } = nav;
  const html = readFileSync(path.join(WEB, "index.html"), "utf8");

  // Le module qui PORTE le modèle est trouvé par ce qu'il définit — pas par son nom.
  const porteurDuModele = modules.find((f) => /^const SPACES\s*=\s*\[/m.test(readFileSync(path.join(WEB, f), "utf8")));
  exiger(!!porteurDuModele, "(35) aucun module ne définit le modèle de navigation `SPACES` : la dérivation n'a plus d'ancre");

  // Les sections de la page, lues DEUX fois : par l'arbre du shim et par le texte d'index.html. Un
  // écart signerait un arbre construit de travers, et le témoin refuserait de conclure.
  const sectionsArbre = sectionsDeLaPage().map((s) => s.id).filter(Boolean);
  const sectionsTexte = [...html.slice(html.indexOf("<main>")).matchAll(/<section[^>]*\bid="([\w-]+)"/g)].map((m) => m[1]);
  exiger(sectionsArbre.length >= 20, `(35) instrument : ${sectionsArbre.length} section(s) dans l'arbre — la construction du document est cassée, le témoin refuse de conclure`);
  // COMPARÉES COMME ENSEMBLES, pas comme suites : la console RÉORDONNE les cartes de la Vue d'ensemble
  // (préférence par utilisateur), donc l'ordre du document n'est pas celui du balisage — et ce n'est
  // pas un défaut. Ce que le témoin tient, c'est que l'arbre porte les MÊMES sections que la page.
  const ecart = [...new Set([...sectionsArbre, ...sectionsTexte])].filter((s) => sectionsArbre.includes(s) !== sectionsTexte.includes(s));
  exiger(ecart.length === 0,
    `(35) instrument : l'arbre du shim et le texte d'index.html ne portent pas les mêmes sections — écart : ${ecart.join(", ")}`);
  exiger(CHARGES_DE_LA_CONSOLE.length >= 20, `(35) instrument : ${CHARGES_DE_LA_CONSOLE.length} charge(s) au registre — lecture cassée`);

  // La section qui CONTIENT la cible d'une charge (ancêtre le plus proche qui est une section de main).
  const sectionDe = (cible, chercheur) => {
    const dep = (chercheur || document).querySelector("#" + cible);
    for (let n = dep; n; n = n.parentNode) if (n.tagName === "SECTION" && sectionsArbre.includes(n.id)) return n.id;
    return null;
  };
  const couverture = (charges) => {
    const m = new Map(sectionsArbre.map((s) => [s, []]));
    for (const c of charges) { const s = sectionDe(c.cible); if (s && m.has(s)) m.get(s).push(c.cible); }
    return m;
  };
  const orphelines = (charges) => sectionsArbre.filter((s) => !couverture(charges).get(s).length && !SECTIONS_SANS_CHARGE.includes(s));

  // (a) COUVERTURE.
  const nues = orphelines(CHARGES_DE_LA_CONSOLE);
  exiger(nues.length === 0, `(35a) ${nues.length} section(s) de la page qu'AUCUNE charge ne peint et qu'aucune raison ne couvre : ${nues.join(", ")} — une lecture ratée au démarrage n'y serait jamais rejouée (c'est le défaut mesuré de P11.14-e). Déclarer la charge, ou nommer la section dans la table des sections sans charge avec sa raison.`);
  // LA RAISON D'UNE DISPENSE EST ÉCRITE, ET ELLE CITE UNE CLÉ QUI EXISTE. Le commentaire qui précède
  // immédiatement la déclaration doit nommer chaque section dispensée et au moins une clé de roadmap,
  // et cette clé doit figurer dans l'index public — sinon la dispense renvoie dans le vide.
  const srcDispense = readFileSync(path.join(WEB, porteurDuModele), "utf8");
  const lignes = srcDispense.split("\n");
  const posDispense = lignes.findIndex((l) => /^const SECTIONS_SANS_CHARGE\s*=/.test(l));
  // Le bloc de commentaire CONTIGU qui précède la déclaration : c'est là que vit la raison, comme
  // partout ailleurs dans ce dépôt. Remonter tant que la ligne est un commentaire.
  const bloc = [];
  for (let i = posDispense - 1; i >= 0 && /^\s*\/\//.test(lignes[i]); i--) bloc.unshift(lignes[i]);
  const avant = bloc.join("\n");
  const clesCitees = [...new Set([...avant.matchAll(/\bP\d+\.\d+-[a-z]\b/g)].map((m) => m[0]))];
  exiger(posDispense >= 0, "(35a) la table des sections dispensées de charge n'est plus déclarée sous une forme lisible : la dispense ne peut plus être jugée");
  const roadmap = readFileSync(path.join(RACINE, "docs", "ROADMAP.md"), "utf8");
  exiger(/\bP\d+\.\d+-[a-z]\b/.test(roadmap), "(35a) instrument : aucune clé lue dans l'index public — la lecture est cassée, le témoin refuse de conclure");
  for (const s of SECTIONS_SANS_CHARGE) {
    exiger(sectionsArbre.includes(s), `(35a) « ${s} » est dispensée de charge mais n'est pas une section de la page : une dispense périmée cache une section réellement découverte`);
    exiger(new RegExp("`" + s + "`").test(avant), `(35a) la section « ${s} » est dispensée sans que le commentaire qui précède la déclaration la NOMME : une dispense sans raison est un oubli déguisé en décision`);
    exiger(!couverture(CHARGES_DE_LA_CONSOLE).get(s).length, `(35a) « ${s} » est dispensée de charge ET peinte par ${couverture(CHARGES_DE_LA_CONSOLE).get(s).join(", ")} : la déclaration ment`);
  }
  exiger(clesCitees.length > 0, "(35a) la dispense n'est adossée à AUCUNE clé de roadmap : une décision sans clé n'a ni mesure ni réfutation derrière elle");
  const clesInconnues = clesCitees.filter((k) => !roadmap.includes(k));
  exiger(clesInconnues.length === 0, `(35a) clé(s) citées par la dispense et absentes de l'index public : ${clesInconnues.join(", ")} — la raison renvoie dans le vide`);

  // (b) AUCUN NOM D'ONGLET NE DÉCIDE.
  const srcModele = readFileSync(path.join(WEB, porteurDuModele), "utf8");
  const sansCommentaires = srcModele.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  const idsDOnglet = MODELE.flatMap((sp) => sp.tabs.map((t) => t.id));
  exiger(idsDOnglet.length >= 20, `(35b) instrument : ${idsDOnglet.length} onglet(s) dérivés du modèle — lecture cassée`);
  const comparaisons = idsDOnglet.filter((id) => new RegExp("[!=]==?\\s*'" + id + "'|'" + id + "'\\s*[!=]==?").test(sansCommentaires));
  exiger(comparaisons.length === 0,
    `(35b) ${comparaisons.length} identifiant(s) d'onglet SERVENT DE CONDITION dans « ${porteurDuModele} » : ${comparaisons.join(", ")}. Une chaîne de conditions sur un nom d'onglet oublie l'onglet posé demain — elle en avait oublié six et en servait un deux fois. Ce qu'un onglet fait se DÉCLARE dans son modèle, ou se DÉDUIT du document.`);

  // (c) et (d) PÉRIMÈTRE et COUVERTURE PAR ONGLET, onglet par onglet, sur l'arbre réel.
  const sansCharge = new Set(SECTIONS_SANS_CHARGE);
  let ongletsVus = 0, ongletsMuets = [];
  for (const sp of MODELE) for (const t of sp.tabs) {
    sectionsDeLaPage().forEach((s) => { s.hidden = !t.sections.includes(s.id); });
    const dansLaVue = nav.chargesDeLaVueAffichees().map((c) => c.cible);
    const attendues = CHARGES_DE_LA_CONSOLE.filter((c) => t.sections.includes(sectionDe(c.cible))).map((c) => c.cible);
    exiger(dansLaVue.slice().sort().join(",") === attendues.slice().sort().join(","),
      `(35c) onglet « ${t.id} » : les charges rejouées à l'entrée [${dansLaVue.join(", ")}] ne sont pas celles de ses sections [${attendues.join(", ")}]`);
    for (const c of nav.chargesVivesAffichees()) {
      const s = sectionDe(c.cible);
      exiger(!s || !sansCharge.has(s), `(35c) onglet « ${t.id} » : la cadence viserait « ${c.cible} », dans la section « ${s} » déclarée SANS charge — c'est exactement ce que P11.17-a refuse`);
    }
    if (!attendues.length && !t.sections.every((s) => sansCharge.has(s) || !sectionsArbre.includes(s))) ongletsMuets.push(t.id);
    ongletsVus++;
  }
  exiger(ongletsVus >= 20, `(35d) instrument : ${ongletsVus} onglet(s) parcourus — lecture cassée`);
  exiger(ongletsMuets.length === 0, `(35d) ${ongletsMuets.length} onglet(s) n'ont AUCUNE charge et ne déclarent pas pourquoi : ${ongletsMuets.join(", ")}`);

  // ---- L'INSTRUMENT SE VALIDE : quatre fautes injectées, que la dérivation doit VOIR. ----
  const ampute = CHARGES_DE_LA_CONSOLE.filter((c) => c.cible !== "rules");
  exiger(orphelines(ampute).includes("rules"), "(35-témoin) une charge RETIRÉE du registre n'est pas vue : la couverture rendrait vert sur un panneau que plus rien ne peint");
  const detourne = CHARGES_DE_LA_CONSOLE.concat([{ cible: "sql", charger: () => {}, vive: true }]);
  exiger(couverture(detourne).get("query").length > 0, "(35-témoin) une charge visant une section déclarée sans charge n'est pas vue : la dispense pourrait mentir sans rougir");
  const plat = { querySelector: () => new Element("div") };   // l'arbre ABSENT — le trou de P11.13-e
  exiger(sectionDe("rules", plat) === null && sectionDe("rules") === "rules",
    "(35-témoin) sans arbre de page, la section d'une charge est introuvable et TOUT paraîtrait couvert ou affiché : c'est le faux vert que P11.13-e a fermé, et il doit rester visible ici");
  const vide = CHARGES_DE_LA_CONSOLE.filter((c) => sectionDe(c.cible) !== "cases");
  exiger(orphelines(vide).includes("cases"), "(35-témoin) un onglet vidé de ses charges n'est pas vu");

  sectionsDeLaPage().forEach((s) => { s.hidden = false; });
  const vives = CHARGES_DE_LA_CONSOLE.filter((c) => c.vive).length;
  console.log(`[charges] ${CHARGES_DE_LA_CONSOLE.length} charges déclarées dans « ${porteurDuModele} », dont ${vives} VIVES (celles dont la cadence dérive son périmètre) ; ${sectionsArbre.length} sections de la page toutes peintes ou dispensées avec leur raison (${SECTIONS_SANS_CHARGE.join(", ") || "aucune dispense"}, adossée à ${clesCitees.join(", ")}) ; ${ongletsVus} onglets parcourus sur l'arbre réel, aucun muet, aucune charge de cadence dans une section dispensée, et AUCUN identifiant d'onglet ne sert de condition. Ce que ce témoin NE tient PAS : qu'une charge peigne réellement sa cible — il tient qui est CENSÉ peindre quoi, pas le contenu peint ; et il ne voit pas un masquage par feuille de style, seulement l'attribut du document.`);
}

// ---------------------------------------------------------------------------------------------
// 36. UN NŒUD N'A QU'UN PARENT (`P11.13-e`). Le shim posait le nouveau parent sans retirer l'enfant de
//     la liste de l'ancien : un élément DÉPLACÉ restait listé sous les deux, ce que le vrai document
//     ne fait jamais. Ce n'est pas une coquette­rie d'instrument — la mesure qui en a dépendu a conclu
//     qu'un formulaire restait joignable après la fermeture des modales alors qu'il ne l'était pas :
//     un FAUX NÉGATIF sur le défaut même que l'instrument servait à établir.
//     (a) Les quatre chemins d'insertion détachent : `appendChild`, `insertBefore`, `prepend`,
//         « replaceChildren » (celui-ci doit aussi ORPHELINER ce qu'il retire).
//     (b) LE DOCUMENT RÉEL, après le chargement de toute la console — qui DÉPLACE réellement des
//         sections (l'ordre des cartes de la Vue d'ensemble est une préférence par utilisateur) —
//         ne contient aucun nœud listé sous deux parents.
//     (c) TÉMOIN NÉGATIF : le comportement d'AVANT, reconstitué à la main sur deux nœuds jetables, est
//         VU par le même vérificateur. Sans lui, (a) et (b) pourraient passer sur un vérificateur muet.
// ---------------------------------------------------------------------------------------------
{
  const deuxParents = (racine) => {
    const vus = new Map(), fautes = [];
    const marcher = (n) => {
      for (const c of n.children || []) {
        if (vus.has(c)) fautes.push(`${c.tagName}${c.id ? "#" + c.id : ""} listé sous ${vus.get(c)} ET sous ${n.tagName}${n.id ? "#" + n.id : ""}`);
        else { vus.set(c, n.tagName + (n.id ? "#" + n.id : "")); marcher(c); }
      }
    };
    marcher(racine);
    return { fautes, vus: vus.size };
  };

  // (c) LE TÉMOIN NÉGATIF D'ABORD : sans lui, un vérificateur muet rendrait (a) et (b) vides de sens.
  const vieuxA = new Element("div"), vieuxB = new Element("div"), errant = new Element("span");
  vieuxA._enfants.push(errant); vieuxA._v++; vieuxB._enfants.push(errant); vieuxB._v++; errant.parentNode = vieuxB;   // le shim d'AVANT
  const porteur = new Element("div"); porteur._enfants.push(vieuxA, vieuxB); porteur._v++;
  exiger(deuxParents(porteur).fautes.length === 1,
    "(36c) le vérificateur ne VOIT PAS un nœud listé sous deux parents : les témoins (a) et (b) ne prouveraient rien");

  // (a) LES QUATRE CHEMINS.
  for (const [nom, poser] of [
    ["appendChild", (b, n) => b.appendChild(n)],
    ["insertBefore", (b, n) => b.insertBefore(n, null)],
    ["prepend", (b, n) => b.prepend(n)],
    ["replaceChildren", (b, n) => b.replaceChildren(n)],
  ]) {
    const a = new Element("div"), b = new Element("div"), n = new Element("p");
    a.appendChild(n);
    poser(b, n);
    exiger(!a.children.includes(n), `(36a) ${nom} : le nœud reste listé sous son ANCIEN parent — un élément déplacé apparaîtrait deux fois`);
    exiger(!a.contains(n), `(36a) ${nom} : l'ancien parent CONTIENT encore le nœud déplacé`);
    exiger(n.parentNode === b && b.children.includes(n), `(36a) ${nom} : le nœud n'est pas correctement rattaché à son nouveau parent`);
  }
  const p0 = new Element("div"), enfant = new Element("i");
  p0.appendChild(enfant); p0.replaceChildren();
  exiger(enfant.parentNode === null, "(36a) replaceChildren : ce qu'il RETIRE garde son ancien parent — un nœud sorti du document s'y croirait encore");

  // (b) LE DOCUMENT RÉEL, tous les modules chargés (donc après les déplacements que la console opère).
  const bilan = deuxParents(document.body);
  exiger(bilan.vus > 500, `(36b) instrument : ${bilan.vus} nœud(s) parcourus dans le document — l'arbre n'est pas construit, le témoin refuse de conclure`);
  exiger(bilan.fautes.length === 0, `(36b) ${bilan.fautes.length} nœud(s) du document listés sous DEUX parents : ${bilan.fautes.slice(0, 5).join(" ; ")}`);

  console.log(`[un-seul-parent] ${bilan.vus} nœuds du document parcourus après chargement de toute la console : aucun sous deux parents. Les quatre chemins d'insertion détachent, « replaceChildren » orpheline ce qu'il retire, et le vérificateur VOIT le comportement d'avant reconstitué à la main. Ce que ce témoin NE tient PAS : l'ordre des nœuds, ni le fait qu'un déplacement soit VOULU — seulement qu'il n'en reste pas de copie.`);
}

// ---------------------------------------------------------------------------------------------
// 37. UNE RECHERCHE DE LISTE SURVIT AU RENDU QUI DÉTRUIT SON CHAMP, ET CE QUE CONSERVER CACHE SE DIT
//     (`P11.18-z`).
//     CE QUE CE TÉMOIN RECONSTITUE, et c'est ce qui le rend concluant : un rechargement de vue ne
//     redessine pas dans le même hôte — il en FABRIQUE un neuf. Chaque « rendu » ci-dessous construit
//     donc un `Element` NEUF et rappelle la fabrique, et le témoin épingle d'abord que le champ du
//     second rendu n'est pas celui du premier ; sans cette vérification, un banc qui repeindrait dans le
//     même hôte validerait une mémoire qui n'existe pas.
//     (a) LE DÉFAUT SÛR, D'ABORD. Une liste qui ne déclare AUCUNE identité n'a pas de mémoire et rend
//         exactement ce qu'elle rendait : même nombre de zones dans l'hôte, champ vide, aucun avis.
//     (b) AVEC UNE IDENTITÉ, la recherche est reposée ET la liste est filtrée — restaurer le texte sans
//         filtrer rendrait une liste entière sous un champ qui dit le contraire.
//     (c) UNE LIGNE APPARUE QUE LA RECHERCHE MASQUE EST ANNONCÉE, avec son NOMBRE, ce que ce nombre ne
//         tient pas, et le geste de tout revoir. TÉMOIN INVERSE : une ligne apparue que la recherche
//         MONTRE n'est annoncée par rien — l'avis se déclenche sur le MASQUAGE, pas sur l'apparition.
//     (d) LE GESTE RÉVÈLE ET OUBLIE : la liste entière revient, l'avis et le résumé partent avec elle,
//         et le rendu suivant ne fait pas renaître la recherche que l'exploitant vient d'effacer.
//     (e) LA LIMITE, RENDUE OBSERVABLE. En mode SERVI, le total est la PAGE servie : un nombre de lignes
//         masquées n'y a pas le même sens d'un rendu à l'autre, donc l'avis n'est PAS armé — alors même
//         que la situation qui l'aurait déclenché est fabriquée ici. La recherche, elle, y survit.
// ---------------------------------------------------------------------------------------------
{
  const { pagedList } = await import(pathToFileURL(path.join(WEB, "core.js")).href);
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const aLaClasse = (e, c) => e.classList && e.classList.contains(c);
  const champDe = (h) => cueillir(h, (e) => e.tagName === "INPUT", [])[0];
  const avisDe = (h) => cueillir(h, (e) => aLaClasse(e, "recherche-annonce"), [])[0];
  const resumeDe = (h) => cueillir(h, (e) => aLaClasse(e, "recherche-resume"), [])[0];
  const lignesRendues = (h) => cueillir(h, (e) => e.tagName === "TR", []).filter((tr) => cueillir(tr, (e) => e.tagName === "TD", []).length > 0);
  const frapper = (h, texte) => { const c = champDe(h); c.value = texte; c.dispatchEvent({ type: "input" }); };
  const colonnes = [{ key: "nom", label: "Nom" }, { key: "etat", label: "État" }];
  const lot = [{ nom: "web-01", etat: "muet" }, { nom: "web-02", etat: "frais" }, { nom: "db-01", etat: "frais" }];
  const lotPlusMasquee = lot.concat([{ nom: "db-02", etat: "muet" }]);        // une ligne de plus, que « web » MASQUE
  const lotPlusVisible = lot.concat([{ nom: "web-03", etat: "frais" }]);      // une ligne de plus, que « web » MONTRE
  const rendre = (identite, lignes) => {
    const hote = new Element("div");
    const o = { mode: "client", pageSize: 50, rows: lignes, columns: colonnes, emptyText: "aucune", recherche: true };
    if (identite) o.storeKey = identite;
    pagedList(hote, o);
    return hote;
  };

  // (a) SANS IDENTITÉ — le comportement d'aujourd'hui, au nœud près.
  const a1 = rendre("", lot);
  exiger(a1.children.length === 3, `(37a) une liste sans identité rend ${a1.children.length} zones dans son hôte au lieu des 3 d'avant : le mécanisme s'impose à qui n'en veut pas`);
  exiger(lignesRendues(a1).length === 3, `(37a) instrument : ${lignesRendues(a1).length} ligne(s) rendues sans recherche au lieu de 3`);
  frapper(a1, "web");
  exiger(lignesRendues(a1).length === 2, `(37a) instrument : la recherche ne filtre pas la liste (${lignesRendues(a1).length} lignes)`);
  const a2 = rendre("", lot);
  exiger(champDe(a2).value === "" && lignesRendues(a2).length === 3, `(37a) une liste SANS identité a gardé une mémoire (« ${champDe(a2).value} ») : le défaut sûr exigé n'est pas tenu`);
  exiger(!avisDe(a2), "(37a) une liste sans identité rend un avis de lignes masquées");

  // (b) AVEC IDENTITÉ — la recherche survit à la destruction de son champ.
  const b1 = rendre("banc_p1118z_flotte", lot);
  exiger(b1.children.length === 4, `(37b) une liste à identité ne pose pas la zone d'avis (${b1.children.length} zones)`);
  frapper(b1, "web");
  exiger(lignesRendues(b1).length === 2, "(37b) instrument : la recherche frappée ne filtre pas");
  const b2 = rendre("banc_p1118z_flotte", lot);
  exiger(champDe(b2) !== champDe(b1) && b2 !== b1, "(37b) instrument : le second rendu réutilise le champ du premier — il ne reconstitue PAS un rechargement de vue, et rien de ce qui suit ne prouverait quoi que ce soit");
  exiger(champDe(b2).value === "web", `(37b) la recherche n'a pas survécu au rendu qui détruit son champ : « ${champDe(b2).value} »`);
  exiger(lignesRendues(b2).length === 2, `(37b) le texte est reposé dans le champ mais la liste rend ${lignesRendues(b2).length} lignes : le champ dit une chose, la liste une autre`);
  exiger(!!resumeDe(b2), "(37b) la liste restaurée ne dit plus qu'elle est filtrée");
  exiger(!avisDe(b2), "(37b) sans aucune ligne apparue, la liste annonce quand même des lignes masquées en plus");

  // (c) UNE LIGNE APPARUE QUE LA RECHERCHE MASQUE — et le témoin inverse.
  const c1 = rendre("banc_p1118z_flotte", lotPlusMasquee);
  const avis = avisDe(c1);
  exiger(!!avis, "(37c) une ligne apparue que la recherche masque n'est annoncée par rien : elle est invisible ET tue, ce qui est le défaut que cette clé poursuit");
  exiger(/(^|\D)1(\D|$)/.test(avis.textContent), `(37c) l'avis ne porte pas le NOMBRE de lignes masquées en plus : « ${avis.textContent} »`);
  exiger(/diff/i.test(avis.textContent), `(37c) l'avis ne dit pas qu'il est une DIFFÉRENCE de comptes — il laisserait croire qu'il a identifié les lignes : « ${avis.textContent} »`);
  // Le témoin RAPPORTE, il n'interrompt pas : sans cette précaution, un avis absent ferait LEVER ce banc
  // au lieu de le faire rougir, et les sections suivantes ne rendraient plus de verdict du tout.
  const bouton = avis ? cueillir(avis, (e) => e.tagName === "BUTTON", [])[0] : null;
  exiger(!!bouton && bouton.classList.contains("btn"), "(37c) l'avis n'offre aucun geste habillé pour révéler les lignes qu'il annonce");
  const d1 = rendre("banc_p1118z_visible", lot);
  frapper(d1, "web");
  const d2 = rendre("banc_p1118z_visible", lotPlusVisible);
  exiger(lignesRendues(d2).length === 3, `(37c) instrument : la ligne ajoutée n'est pas rendue par la recherche (${lignesRendues(d2).length} lignes)`);
  exiger(!avisDe(d2), "(37c) témoin inverse : une ligne apparue que la recherche MONTRE est annoncée comme masquée — l'avis se déclenche sur l'apparition au lieu du masquage");

  // (d) LE GESTE RÉVÈLE, ET IL OUBLIE.
  if (bouton) {
    bouton.dispatchEvent({ type: "click" });
    exiger(champDe(c1).value === "" && lignesRendues(c1).length === 4, `(37d) le geste de l'avis ne rend pas la liste entière (${lignesRendues(c1).length} lignes, champ « ${champDe(c1).value} »)`);
    exiger(!avisDe(c1) && !resumeDe(c1), "(37d) après avoir tout révélé, la liste dit encore qu'elle cache quelque chose");
  } else exiger(false, "(37d) aucun geste à exercer : l'avis n'en offre pas, et ce que ce geste doit produire n'est mesuré par personne");
  const e1 = rendre("banc_p1118z_flotte", lotPlusMasquee);
  exiger(champDe(e1).value === "", `(37d) une recherche VIDÉE renaît au rendu suivant (« ${champDe(e1).value} ») : le souvenir survit au geste qui l'efface`);

  // (e) MODE SERVI — la recherche survit, l'avis n'est PAS armé, et la situation qui l'aurait déclenché
  //     est fabriquée pour que le témoin ne soit pas vide de sens.
  const servir = (lignes) => async () => ({ rows: lignes, total: 137 });
  const rendreServi = (lignes) => {
    const hote = new Element("div");
    pagedList(hote, { mode: "server", pageSize: 50, fetchPage: servir(lignes), columns: colonnes, recherche: true, storeKey: "banc_p1118z_servi" });
    return hote;
  };
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const s1 = rendreServi(lot); await tick();
  exiger(lignesRendues(s1).length === 3, `(37e) instrument : la liste servie ne rend pas ses 3 lignes (${lignesRendues(s1).length})`);
  frapper(s1, "web"); await tick();
  exiger(lignesRendues(s1).length === 2, `(37e) instrument : la recherche ne filtre pas la page servie (${lignesRendues(s1).length})`);
  const s2 = rendreServi(lotPlusMasquee); await tick();
  exiger(champDe(s2).value === "web", `(37e) en mode servi la recherche n'est pas conservée : « ${champDe(s2).value} »`);
  exiger(lignesRendues(s2).length === 2, `(37e) instrument : la page servie suivante n'est pas filtrée (${lignesRendues(s2).length}) — l'écart de masquage n'existerait pas`);
  exiger(!avisDe(s2), "(37e) l'avis est armé sur une page SERVIE : son compte varie avec la page, il annoncerait des lignes apparues là où l'on a seulement tourné la page");

  console.log(`[recherche-persistante] une recherche de liste survit au rendu qui DÉTRUIT son champ, sous la seule condition d'une identité de liste — sans identité, mêmes zones, même champ vide, aucun avis ; avec elle, le texte est reposé ET la liste filtrée, une ligne apparue que la recherche masque est annoncée par un NOMBRE qui dit être une différence de comptes et porte le geste de tout revoir, une ligne apparue qu'elle MONTRE n'est annoncée par rien, et le geste de révéler oublie le souvenir au lieu de le laisser renaître. Ce que ce témoin NE tient PAS : rien de la mise en page ni du style calculé, et l'avis n'est pas armé en mode servi — c'est vérifié ici sur la situation même qui l'aurait déclenché.`);
}

// ---------------------------------------------------------------------------------------------
// 38. L'ACQUITTEMENT PAR LISTE DIT CE QU'IL COUVRE, ET POURQUOI LE GESTE À FACETTE N'EXISTE PAS
//     (`P11.1-g`).
//     LE CONSTAT : sous la facette d'une source, « Acquitter les N affichée(s) » se lit comme
//     « acquitter tout ce qui relève de cette source ». Ce geste-là N'EXISTE PAS — l'unique route
//     d'acquittement en masse du démon ne prend aucun filtre — et rien ne le disait.
//     (a) TÉMOIN NÉGATIF D'ABORD : sans aucun filtre posé, le geste OFFERT est le geste GLOBAL, son
//         libellé et son survol sont ceux d'avant, et la phrase du filtre n'apparaît nulle part. Sans
//         ce témoin, (b) passerait sur une phrase collée partout.
//     (b) SOUS UN FILTRE : le survol du bouton dit les TROIS choses — ce que le geste atteint, pourquoi
//         le geste à facette n'est pas offert, et ce qui reste hors d'atteinte.
//     (c) LA PHRASE DU RESTE EST DÉRIVÉE DE LA RÉPONSE DU DÉMON, PROUVÉ PAR MUTATION : à modèle
//         IDENTIQUE, la SEULE valeur qui change est `loaded.total` — la population que le démon
//         déclare. Déclarée, la console dit « les autres pages ne sont pas touchées » ; non déclarée,
//         elle dit qu'elle NE PEUT PAS savoir s'il en reste. Aucune borne (200) n'est recopiée : c'est
//         l'ABSENCE de `total` qui porte l'aveu.
//     (d) LE SURVOL ET LA CONFIRMATION ONT UN SEUL AUTEUR — la propriété est lue dans le SOURCE, parce
//         que c'est la DIVERGENCE qui serait le défaut : un bouton qui promet une portée et une
//         question qui en engage une autre. Et le chemin de confirmation de `P11.18-k` n'est pas
//         contourné : `confirmModal` reste appelé d'un SEUL endroit, `acquitter`.
//     (e) LE BOUTON INERTE PORTE LA MÊME RAISON : sous un filtre, un geste sans objet dit AUSSI que
//         « Tout acquitter » n'aurait pas porté ce filtre.
//     CE QUE CE TÉMOIN NE TIENT PAS : il ne prouve pas que le démon refuse un ack-all à facette (il
//     n'en a pas), ni que la liste servie soit complète — elle ne l'est pas, et c'est ce qui est DIT.
// ---------------------------------------------------------------------------------------------
{
  const { alertActionBarHtml, porteeDeLAcquittement } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const src = readFileSync(path.join(WEB, "alerts.js"), "utf8");
  const titreDe = (html, act) => (html.match(new RegExp(`<button[^>]*data-act="${act}"[^>]*title="([^"]*)"`)) || [])[1] || "";
  const MOT_FILTRE = /acquitter tout ce qui relève de ce filtre/;
  const MOT_AFFICHEES = /ne porte que sur les alertes actives AFFICHÉES/;
  const MOT_AUTRES_PAGES = /autres pages de cette liste ne sont pas touchées/;
  const MOT_INCONNU = /borne cette liste sans en déclarer le total/;

  // (a) TÉMOIN NÉGATIF — aucun filtre, portée « actives » : le geste GLOBAL, inchangé.
  const mSansFiltre = { view: "", scopeAll: false, uncased: true, mitre: "", source: "", recherche: "" };
  const sansFiltre = alertActionBarHtml(mSansFiltre, { count: 9, countLabel: "9 alerte(s)", ackableIds: [1, 2, 3] });
  exiger(/data-act="ack-all"/.test(sansFiltre) && !/data-act="ack-shown"/.test(sansFiltre),
    "(38a) sans aucun filtre, la barre n'offre plus l'acquittement GLOBAL : le geste qui existe vraiment a été retiré");
  exiger(titreDe(sansFiltre, "ack-all") === "Acquitter TOUTES les alertes actives (y compris celles hors de cette page)",
    `(38a) le survol du geste global a changé : « ${titreDe(sansFiltre, "ack-all")} » — il est au lexique, le déplacer le laisserait en français`);
  exiger(!MOT_FILTRE.test(sansFiltre) && !MOT_INCONNU.test(sansFiltre),
    "(38a) la phrase du filtre est rendue là où AUCUN filtre n'est posé : elle est collée partout, et (b) ne prouverait rien");

  // (b) SOUS LA FACETTE D'UNE SOURCE, portée « actives » : le démon ne déclare aucun total.
  const mSource = { view: "", scopeAll: false, uncased: false, mitre: "", source: "k8s-audit", recherche: "" };
  const chargeSansTotal = { count: 3, countLabel: "3 alerte(s)", ackableIds: [7, 8, 9] };
  const sousSource = alertActionBarHtml(mSource, chargeSansTotal);
  const survolSource = titreDe(sousSource, "ack-shown");
  exiger(MOT_AFFICHEES.test(survolSource), `(38b) le survol ne dit pas CE QUE le geste atteint : « ${survolSource} »`);
  exiger(MOT_FILTRE.test(survolSource), `(38b) le survol ne dit pas que le geste « tout ce qui relève de ce filtre » n'existe pas : « ${survolSource} »`);
  exiger(/la source « k8s-audit »/.test(survolSource), `(38b) le survol ne NOMME pas le filtre posé : « ${survolSource} »`);
  exiger(MOT_INCONNU.test(survolSource), `(38b) le survol ne dit pas ce qui reste hors d'atteinte : « ${survolSource} »`);
  exiger(/Acquitter les 3 affichée\(s\)</.test(sousSource), `(38b) le LIBELLÉ du bouton a changé : ${sousSource.match(/data-act="ack-shown"[^>]*>[^<]*/)?.[0]}`);

  // (c) LA MUTATION — même modèle, même charge, SEUL `total` change.
  const avecTotal = alertActionBarHtml(mSource, { ...chargeSansTotal, total: 137 });
  const survolTotal = titreDe(avecTotal, "ack-shown");
  exiger(MOT_INCONNU.test(survolSource) && !MOT_AUTRES_PAGES.test(survolSource),
    `(38c) sans total déclaré, la console parle pourtant d'autres pages : « ${survolSource} »`);
  exiger(MOT_AUTRES_PAGES.test(survolTotal) && !MOT_INCONNU.test(survolTotal),
    `(38c) avec un total déclaré, la console dit encore qu'elle ignore ce qui reste : « ${survolTotal} »`);
  exiger(survolSource !== survolTotal, "(38c) instrument : la mutation de `total` ne change RIEN au survol — la dérivation est morte");
  exiger(!/\b200\b/.test(survolSource) && !/\b200\b/.test(src.match(/const ACQUITTEMENT_MOTS[\s\S]*?\n};/)[0]),
    "(38c) la borne du démon (200) est RECOPIÉE dans la console : un changement côté démon la rendrait fausse en silence");

  // (d) UN SEUL AUTEUR, et la porte de confirmation n'est pas contournée — lu dans le SOURCE.
  const acq = porteeDeLAcquittement(mSource, chargeSansTotal);
  exiger(survolSource === acq.survol, "(38d) le survol du bouton n'est pas celui que l'auteur unique rend : deux formulations peuvent diverger");
  exiger(acq.phrase.replace(" ? ", ". ") === acq.survol,
    `(38d) la question de la confirmation et le survol ne disent pas la MÊME chose :\n  survol : ${acq.survol}\n  phrase : ${acq.phrase}`);
  exiger(/acquitter\(\{\s*ids,\s*phrase:\s*porteeDeLAcquittement\(m,\s*loaded\)\.phrase\s*\}\)/.test(src),
    "(38d) l'acquittement par liste n'engage plus la phrase de l'auteur unique : la confirmation peut promettre autre chose que le bouton");
  exiger((src.match(/\bconfirmModal\(/g) || []).length === 1 && /async function acquitter\(portee\)\s*\{\s*\n\s*if \(!await confirmModal\(/.test(src),
    "(38d) `confirmModal` n'est plus appelé du seul `acquitter` : un geste d'acquittement peut désormais partir SANS confirmation (`P11.18-k`)");
  exiger(/function porteeDeLAcquittement\(m, loaded\)/.test(src) && (src.match(/const ACQUITTEMENT_MOTS/g) || []).length === 1,
    "(38d) les mots de l'acquittement ont plus d'un auteur : un renommage n'atteindrait qu'une des surfaces");

  // (e) LE BOUTON INERTE PORTE LA MÊME RAISON — et, hors filtre, il ne la porte pas.
  const inerteSousFiltre = alertActionBarHtml({ ...mSource, view: "host" }, { count: 2, countLabel: "2 groupe(s)", ackableIds: [] });
  const motifFiltre = titreDe(inerteSousFiltre, "ack-shown");
  exiger(/dépliez un groupe/.test(motifFiltre) && MOT_FILTRE.test(motifFiltre),
    `(38e) le bouton inerte sous un filtre ne dit pas que « Tout acquitter » n'aurait pas porté ce filtre : « ${motifFiltre} »`);
  const inerteHorsFiltre = alertActionBarHtml({ view: "host", scopeAll: true, uncased: true, mitre: "", source: "", recherche: "" }, { count: 2, countLabel: "2 groupe(s)", ackableIds: [], total: 2 });
  exiger(!MOT_FILTRE.test(titreDe(inerteHorsFiltre, "ack-shown")),
    `(38e) témoin inverse : sans filtre posé, le bouton inerte parle quand même d'un filtre : « ${titreDe(inerteHorsFiltre, "ack-shown")} »`);

  // (f) LE CHEMIN RÉEL, pas seulement la fonction pure : la liste plate DESSINÉE sur un lot servi. C'est
  //     `dessinerLaListePlate` qui remplit `loaded.total` depuis la réponse du démon ; une valeur qui n'y
  //     arriverait pas ferait dire à la barre l'INVERSE de ce que le démon a répondu, sans que (b)-(c) le
  //     voient. Les deux réponses possibles du démon sont jouées sur le MÊME lot.
  {
    const { dessinerLaListePlate, alertListModel } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
    const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
    const liste = new Element("div");
    const etatOrigine = { g: S.alertGroupBy, a: S.alertGroupAll, u: S.alertUncased, s: S.alertSourceFilter, auth: S.AUTH };
    try {
      S.AUTH = { user: "root", role: "admin" };
      S.alertGroupBy = ""; S.alertGroupAll = false; S.alertUncased = false; S.alertSourceFilter = "k8s-audit";
      const lot = [{ id: 1, ts: 1000, rule: "rule.1", severity: 3, title: "Echecs SSH", status: "new", detail: "", mitre: "", sources: "k8s-audit", case_id: null, acked_at: 0, acked_by: "" }];
      dessinerLaListePlate(liste, alertListModel(), lot, undefined);
      const rendueSansTotal = titreDe(String(liste.innerHTML), "ack-shown");
      dessinerLaListePlate(liste, alertListModel(), lot, 137);
      const rendueAvecTotal = titreDe(String(liste.innerHTML), "ack-shown");
      exiger(MOT_FILTRE.test(rendueSansTotal) && /la source « k8s-audit »/.test(rendueSansTotal),
        `(38f) la liste RENDUE sous une facette ne dit pas que le geste à facette n'existe pas : « ${rendueSansTotal} »`);
      exiger(MOT_INCONNU.test(rendueSansTotal) && !MOT_AUTRES_PAGES.test(rendueSansTotal),
        `(38f) le démon n'a déclaré AUCUN total et la liste rendue parle pourtant d'autres pages : « ${rendueSansTotal} »`);
      exiger(MOT_AUTRES_PAGES.test(rendueAvecTotal) && !MOT_INCONNU.test(rendueAvecTotal),
        `(38f) le démon a déclaré un total et la liste rendue dit encore qu'elle ignore ce qui reste — la population déclarée ne remonte pas du chemin réel : « ${rendueAvecTotal} »`);
    } finally {
      S.alertGroupBy = etatOrigine.g; S.alertGroupAll = etatOrigine.a; S.alertUncased = etatOrigine.u;
      S.alertSourceFilter = etatOrigine.s; S.AUTH = etatOrigine.auth;
    }
  }

  console.log(`[acquittement] sous un filtre, l'acquittement par liste NOMME le filtre posé, dit qu'il ne porte que sur les alertes affichées, dit que le geste « tout ce qui relève de ce filtre » n'existe pas côté démon, et dit ce qui reste hors d'atteinte — phrase DÉRIVÉE de la présence d'un total déclaré, prouvée par mutation, jamais d'une borne recopiée ; le survol et la question de la confirmation ont un auteur unique, la porte de confirmation reste seule, et sans filtre le geste GLOBAL et son survol sont inchangés. Ce que ce témoin NE tient PAS : il ne rend pas le geste complet — le démon n'a pas d'acquittement à facette — et il ne dit pas COMBIEN d'alertes lui échappent, parce que personne ne le déclare.`);
}

// ---------------------------------------------------------------------------------------------
// 38b. LE LANGAGE DE REQUÊTE N'A QU'UNE RÉFÉRENCE, ET SON VOCABULAIRE EST DÉRIVÉ DU PRODUIT (`P11.6-d`).
//     Il y en avait DEUX. Celle du guide nommait tout ; celle qu'ouvrait le bouton « ? Aide » de la barre
//     de requête nommait 8 des 20 commandes de pipe — LE CHEMIN LE PLUS FRÉQUENTÉ MENAIT AU TEXTE LE PLUS
//     PAUVRE. La cause n'était pas la pauvreté du texte mais son ISOLEMENT : rien ne DÉRIVAIT la liste des
//     commandes de l'aide depuis la déclaration du produit, et la divergence s'est donc installée sans que
//     rien ne rougisse. La seconde référence est supprimée ; ce témoin ferme le chemin qui l'a laissée
//     naître, il n'ajoute pas un drapeau.
//     CE QU'IL TIENT. (a) Les SIX vocabulaires que `daemon/src/handlers/soql_meta.rs` DÉCLARE (bases,
//     commandes de pipe, mesures, fonctions d'eval, opérateurs de filtre, mots-clés) sont confrontés à
//     l'ensemble des jetons que la référence RENDUE écrit, DANS LES DEUX SENS et DANS LES DEUX LANGUES :
//     un jeton déclaré qui manque à la référence est un trou, un jeton écrit que le produit ne déclare pas
//     est une invention. (b) La porte de la barre de requête (`openHelpModal`) et celle du guide rendent
//     le MÊME texte, caractère pour caractère : il ne peut plus y avoir un pire chemin. (c) Aucune AUTRE
//     section du registre n'est une seconde référence — le critère est DÉRIVÉ (nommer un quart ou plus des
//     commandes déclarées), pas une liste de clés interdites, donc une seconde référence sous un nom neuf
//     rougirait aussi.
//     L'INSTRUMENT SE VALIDE AVANT DE CONCLURE : les six vocabulaires lus non vides ; l'extracteur de
//     jetons éprouvé sur un corpus TÉMOIN à double sens — il DOIT lire les lignes d'item (deux espaces, le
//     jeton, deux espaces au moins), il NE DOIT PAS lire la prose de colonne zéro, les exemples indentés de
//     quatre, ni une ligne d'item dont le jeton n'est séparé que par UN espace ; et le texte lu vient du
//     panneau RENDU, jamais de la source du registre.
//     CE QU'IL NE TIENT PAS, ET C'EST MESURÉ ICI PLUTÔT QUE SUPPOSÉ : le LIBELLÉ de chaque description
//     (celui de la console, dans deux langues là où le démon n'en porte qu'une, en français) ; la liste des
//     CHAMPS de la première étape, dont la déclaration vit dans le cœur partagé et n'est pas lisible de ce
//     dépôt ; et le GLOSSAIRE du guide, qui définit quelques-uns des mêmes mots sans prétendre énumérer le
//     langage — le nombre de commandes déclarées qu'il redéfinit est DÉRIVÉ et publié ci-dessous, et une
//     commande retirée du langage y survivrait sans que ce témoin le voie.
// ---------------------------------------------------------------------------------------------
{
  const DECLARATION = path.join(RACINE, "daemon", "src", "handlers", "soql_meta.rs");
  const rsq = readFileSync(DECLARATION, "utf8");
  const vocabulaire = (nom) => {
    const m = rsq.match(new RegExp(`const ${nom}: &\\[\\(&str, &str\\)\\] = &\\[([\\s\\S]*?)\\n\\];`));
    exiger(!!m, `(38) vocabulaire \`${nom}\` introuvable dans la déclaration du démon : le témoin ne lit plus ce qu'il juge`);
    return m ? [...m[1].replace(/\s+/g, " ").matchAll(/\(\s*"((?:[^"\\]|\\.)*)"\s*,/g)].map((e) => e[1]) : [];
  };
  // Le vocabulaire AVEC son libellé : même ancre, même bloc, mais la description est gardée. C'est ce que
  // la jambe (d) confronte à la borne déclarée par le corpus ; le démon n'en porte qu'en français.
  const paires = (nom) => {
    const m = rsq.match(new RegExp(`const ${nom}: &\\[\\(&str, &str\\)\\] = &\\[([\\s\\S]*?)\\n\\];`));
    return m ? [...m[1].replace(/\s+/g, " ").matchAll(/\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)/g)].map((e) => [e[1], e[2]]) : [];
  };
  // Les six vocabulaires que la complétion sert (`/api/soql/schema`) et que le compilateur fermé accepte :
  // `soql_docs_cover_all_vocab` exige côté démon qu'ils couvrent 1:1 les consts `SOQL_*` du cœur.
  const NOMS = ["DOC_BASE_KEYWORDS", "DOC_COMMANDS", "DOC_STATS_FUNCTIONS", "DOC_EVAL_FUNCTIONS", "DOC_OPERATORS", "DOC_KEYWORDS"];
  const parVocabulaire = new Map(NOMS.map((n) => [n, vocabulaire(n)]));
  const COMMANDES = parVocabulaire.get("DOC_COMMANDS") || [];
  const declares = new Set([...parVocabulaire.values()].flat());

  // — instrument : aucun vocabulaire lu vide, sans quoi le verdict ne mesure rien.
  const vides = NOMS.filter((n) => (parVocabulaire.get(n) || []).length === 0);
  exiger(vides.length === 0, `(38) ${vides.length} vocabulaire(s) lus VIDES dans la déclaration du démon : ${vides.join(", ")} — le témoin refuse de conclure`);

  // L'extracteur de jetons : une ligne d'ITEM de la référence porte DEUX espaces, le jeton, puis DEUX
  // espaces au moins avant sa description. La forme est écrite à côté du registre ; elle est la seule de ce
  // corps, prose et exemples ayant une autre indentation.
  const jetonsDe = (t) => new Set([...String(t).matchAll(/^ {2}(\S+) {2,}\S/gm)].map((m) => m[1]));

  // — instrument, DANS LES DEUX SENS : ce que l'extracteur doit lire, et ce qu'il ne doit PAS lire.
  const CORPUS = [
    "PIPELINE :  <base> <filtres>  | commande  | commande",   // prose de colonne zéro : ignorée
    "  stats       agrège les événements",                     // item : lu
    "  span=       taille de l'intervalle",                    // item dont le jeton porte un signe : lu
    "  =~          correspondance par expression régulière",   // item dont le jeton est un opérateur : lu
    "  motnu description",                                     // UN seul espace : ce n'est pas un item
    "    search source=ufw | stats count by src_ip",           // exemple indenté de quatre : ignoré
    "    limit:N / max:N     borne le nombre de lignes",        // remarque indentée de quatre : ignorée
  ].join("\n");
  const lu = jetonsDe(CORPUS);
  for (const doitLire of ["stats", "span=", "=~"]) exiger(lu.has(doitLire), `(38) instrument : l'extracteur ne lit plus « ${doitLire} » dans son corpus témoin — il ne mesure plus la référence`);
  for (const doitIgnorer of ["motnu", "search", "limit:N", "PIPELINE"]) exiger(!lu.has(doitIgnorer), `(38) instrument : l'extracteur prend « ${doitIgnorer} » pour un item de vocabulaire — il compterait la prose et les exemples`);
  exiger(lu.size === 3, `(38) instrument : ${lu.size} jeton(s) lus sur le corpus témoin, 3 attendus — ${[...lu].join(" ")}`);

  // La référence est lue dans le panneau RENDU, jamais dans la source du registre.
  const SUF = "?plume-lang=en";
  const urlAide = (f, suffixe = "") => pathToFileURL(path.join(WEB, f)).href + suffixe;
  const aideFR = await import(urlAide("help.js"));
  localStorage.setItem("soc_lang", "en");
  const aideEN = await import(urlAide("help.js", SUF));
  localStorage.removeItem("soc_lang");
  const cueillirPre = (el, acc = []) => { if (el.tagName === "PRE") acc.push(el); (el.children || []).forEach((c) => cueillirPre(c, acc)); return acc; };
  const panneau = (ouvrir) => {
    const avant = document.body.children.length;
    ouvrir();
    const ajoutes = document.body.children.slice(avant);
    ajoutes.forEach((n) => n.remove());
    return { n: ajoutes.length, corps: ajoutes.flatMap((n) => cueillirPre(n)).map(texte).join("\n") };
  };

  // (b) LA PORTE DE LA BARRE DE REQUÊTE ET CELLE DU GUIDE RENDENT LE MÊME TEXTE — plus de pire chemin.
  const parLaBarre = panneau(aideFR.openHelpModal);
  const parLeGuide = panneau(() => aideFR.openHelp("soql"));
  exiger(parLaBarre.n === 1 && parLeGuide.n === 1, `(38) la barre de requête rend ${parLaBarre.n} panneau(x) et le guide ${parLeGuide.n} : une porte de la référence ne s'ouvre pas`);
  exiger(parLaBarre.corps.length > 500, `(38) instrument : la référence rendue par la barre fait ${parLaBarre.corps.length} caractère(s) — la lecture du <pre> est cassée`);
  exiger(parLaBarre.corps === parLeGuide.corps, `(38) le bouton « ? Aide » de la barre de requête et le guide ouvrent DEUX textes différents (${parLaBarre.corps.length} vs ${parLeGuide.corps.length} caractères) : le chemin le plus fréquenté peut à nouveau mener au texte le plus pauvre`);

  // (a) LES SIX VOCABULAIRES, DANS LES DEUX SENS, DANS LES DEUX LANGUES.
  const corpsEN = panneau(() => aideEN.openHelp("soql")).corps;
  const rendus = [["fr", parLeGuide.corps], ["en", corpsEN]];
  for (const [langue, corps] of rendus) {
    exiger(corps.trim().length > 0, `(38) la référence ne rend AUCUN texte sous LANG='${langue}'`);
    const ecrits = jetonsDe(corps);
    const manquants = [...declares].filter((t) => !ecrits.has(t));
    const inventes = [...ecrits].filter((t) => !declares.has(t));
    exiger(manquants.length === 0, `(38) sous LANG='${langue}', ${manquants.length} jeton(s) que le produit DÉCLARE et que la référence ne nomme pas : ${manquants.join(" ")} — une référence incomplète qui ne dit pas qu'elle l'est`);
    exiger(inventes.length === 0, `(38) sous LANG='${langue}', ${inventes.length} jeton(s) écrits que la déclaration du démon ne porte pas : ${inventes.join(" ")} — soit le langage a changé, soit une ligne de prose a pris la forme d'un item de vocabulaire`);
  }

  // (c) AUCUNE SECONDE RÉFÉRENCE — critère DÉRIVÉ du vocabulaire déclaré, pas une liste de clés interdites.
  const { HELP } = await import(urlAide("help_registry.js"));
  const SEUIL = Math.ceil(COMMANDES.length / 4);
  const nomme = (t, jeton) => new RegExp(`(^|[^A-Za-z_])${jeton.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}($|[^A-Za-z_])`).test(t);
  const compte = [];
  for (const [cle, e] of Object.entries(HELP)) {
    for (const langue of ["fr", "en"]) {
      const d = e && e[langue];
      if (!d) continue;
      compte.push([`${cle}.${langue}`, COMMANDES.filter((c) => nomme(`${d.title}\n${d.body}`, c)).length]);
    }
  }
  exiger(compte.length > 20, `(38) instrument : ${compte.length} section(s)/langue(s) lues dans le registre — la dérivation est cassée`);
  const references = compte.filter(([, n]) => n >= SEUIL);
  const horsReference = compte.filter(([, n]) => n < SEUIL);
  const plusHauteHors = horsReference.reduce((a, b) => (b[1] > a[1] ? b : a), ["(aucune)", 0]);
  exiger(references.every(([nom]) => nom.startsWith("soql.")),
    `(38) ${references.length} surface(s) d'aide nomment un quart ou plus des ${COMMANDES.length} commandes déclarées, donc plus d'UNE référence du langage : ${references.map(([n, v]) => `${n} (${v})`).join(", ")} — deux porteurs du même savoir, donc deux vérités dès que l'un bouge`);


  // (d) UNE BORNE MESURÉE DU LANGAGE EST PORTÉE PAR TOUTE SURFACE QUI LA DÉCRIT (`P9.7-c`).
  //     LE DÉFAUT, MESURÉ LE 2026-08-27 : ce témoin confrontait l'ENSEMBLE des jetons dans les deux sens
  //     et disait lui-même ne pas tenir le LIBELLÉ des descriptions. Le libellé promettait donc plus que
  //     le langage : `where` était décrit « comparaisons, and/or » là où le compilateur n'accepte QU'UNE
  //     comparaison, et `sort` « un ou plusieurs champs » là où il n'en trie QU'UN. QUATRE libellés
  //     servis portaient la promesse — la déclaration du démon (fr) et l'aide de la console (fr ET en).
  //     Le compilateur, lui, ne refuse pas : il avale le second terme dans un LITTÉRAL DE TEXTE
  //     (`WHERE "count" > '5 and count < 100'`) ou jette le second champ de tri. Un exploitant qui écrit
  //     d'après la description obtient donc une réponse VIDE qui a l'air complète.
  //     LA BORNE N'EST PAS ÉCRITE ICI : elle est DÉCLARÉE PAR LE CORPUS (`docs/GXQL.md`, tableau dont
  //     l'en-tête porte « Commande » et « Phrase exigée »), et ce témoin exige que chaque surface qui
  //     décrit la commande porte la phrase déclarée. Ajouter une ligne au corpus arme ce témoin sur une
  //     commande de plus sans le toucher ; revenir à « un ou plusieurs champs » retire « un champ » et
  //     fait rougir. Le sens inverse est tenu aussi : une commande bornée par le corpus que le démon ne
  //     DÉCLARE pas est un corpus qui parle d'un langage disparu.
  //     CE QU'IL NE TIENT PAS : il ne COMPILE rien — le compilateur vit dans une caisse externe. Il tient
  //     une cohérence d'ÉCRITURE entre trois surfaces ; la mesure qui a fixé la borne est datée dans le
  //     corpus (§3.1, §10). Et il ne juge QUE les commandes que le corpus borne : une borne jamais
  //     déclarée reste invisible, ce qu'un PLANCHER rend au moins visible en refusant de conclure sous
  //     deux bornes déclarées.
  const CORPUS_LANGAGE = path.join(RACINE, "docs", "GXQL.md");
  // Le tableau est DÉRIVÉ de son EN-TÊTE, jamais d'un numéro de ligne ni d'un titre de section : le
  // document peut être réorganisé, la garde suit la propriété.
  const bornesDuCorpus = (texte) => {
    const l = String(texte).split("\n");
    const i = l.findIndex((x) => /^\|\s*Commande\s*\|/.test(x) && /Phrase exigée \(fr\)/.test(x) && /Phrase exigée \(en\)/.test(x));
    if (i < 0) return null;
    const out = [];
    for (let k = i + 2; k < l.length; k++) {
      if (!/^\|/.test(l[k])) break;
      const c = l[k].split("|").slice(1, -1).map((x) => x.trim());
      if (c.length !== 4) break;
      const cmd = (c[0].match(/^`([^`]+)`$/) || [])[1];
      const fr = (c[2].match(/^`([^`]+)`$/) || [])[1];
      const en = (c[3].match(/^`([^`]+)`$/) || [])[1];
      if (cmd && fr && en) out.push({ cmd, fr, en });
    }
    return out;
  };
  // La ligne d'ITEM d'une commande dans la référence RENDUE : même forme que l'extracteur de jetons.
  const echappe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const ligneItem = (corps, jeton) => {
    const m = String(corps).match(new RegExp(`^ {2}${echappe(jeton)} {2,}(.*)$`, "m"));
    return m ? m[1] : null;
  };
  // — instrument, DANS LES DEUX SENS, hors du disque : ce que la lecture doit voir, et ce qu'elle ne
  //   doit pas prendre pour une borne.
  {
    const TEMOIN = [
      "| Commande | Ce que le langage tient | Phrase exigée (fr) | Phrase exigée (en) |",
      "|---|---|---|---|",
      "| `sort` | UN champ | `un champ` | `one field` |",
      "| prose | pas de dosseret | `x` | `y` |",
      "",
      "| Commande | Autre chose | Encore |",
      "|---|---|---|",
      "| `top` | a | b |",
    ].join("\n");
    const vu = bornesDuCorpus(TEMOIN);
    exiger(!!vu && vu.length === 1 && vu[0].cmd === "sort" && vu[0].fr === "un champ" && vu[0].en === "one field",
      `(38d) instrument : la lecture du tableau de bornes rend ${vu ? JSON.stringify(vu) : "rien"} sur son corpus témoin — 1 borne \`sort\` attendue, ni la ligne sans dosseret ni le tableau à trois colonnes`);
    exiger(bornesDuCorpus("aucun tableau ici") === null,
      `(38d) instrument : la lecture prétend trouver un tableau de bornes là où il n'y en a pas`);
    exiger(ligneItem("  sort        trie sur un champ", "sort") === "trie sur un champ",
      `(38d) instrument : la lecture d'une ligne d'item de la référence est cassée`);
    exiger(ligneItem("  sort trie sur un champ", "sort") === null,
      `(38d) instrument : la lecture prend pour un item une ligne qui n'a qu'UN espace — elle lirait de la prose`);
  }
  const bornes = bornesDuCorpus(readFileSync(CORPUS_LANGAGE, "utf8"));
  exiger(!!bornes, `(38d) le corpus \`docs/GXQL.md\` ne déclare plus de tableau de bornes (en-tête « Commande … Phrase exigée (fr) … (en) ») : la borne du langage n'est plus déclarée nulle part, et ce témoin refuse de conclure`);
  const BORNES_MIN = 2;
  exiger(!bornes || bornes.length >= BORNES_MIN, `(38d) le corpus ne déclare plus que ${bornes ? bornes.length : 0} borne(s) de langage, ${BORNES_MIN} au moins étaient déclarées le 2026-08-27 (\`where\`, \`sort\`) — une borne retirée du corpus désarme ce témoin en silence`);
  const descriptionsDemon = new Map(paires("DOC_COMMANDS"));
  for (const b of bornes || []) {
    exiger(COMMANDES.includes(b.cmd), `(38d) le corpus borne « ${b.cmd} », que le démon ne DÉCLARE pas comme commande de pipe — le corpus décrit un langage qui n'existe plus`);
    const auDemon = descriptionsDemon.get(b.cmd);
    exiger(auDemon != null && auDemon.toLowerCase().includes(b.fr.toLowerCase()),
      `(38d) la description que le démon SERT pour « ${b.cmd} » ne porte pas la borne « ${b.fr} » déclarée par le corpus : ${JSON.stringify(auDemon)} — le texte affiché promet plus que le langage ne tient`);
    for (const [langue, corps, exige] of [["fr", parLeGuide.corps, b.fr], ["en", corpsEN, b.en]]) {
      const ligne = ligneItem(corps, b.cmd);
      exiger(ligne != null, `(38d) sous LANG='${langue}', la référence RENDUE ne porte aucune ligne d'item pour « ${b.cmd} » : la borne ne peut pas y être lue`);
      exiger(ligne == null || ligne.toLowerCase().includes(exige.toLowerCase()),
        `(38d) sous LANG='${langue}', l'aide RENDUE décrit « ${b.cmd} » sans la borne « ${exige} » déclarée par le corpus : ${JSON.stringify(ligne)} — l'exploitant écrit d'après cette ligne et obtient une réponse vide qui a l'air complète`);
    }
  }

  // CE QUE CE TÉMOIN NE TIENT PAS, DÉRIVÉ DU DÉPÔT PLUTÔT QU'ÉCRIT : le glossaire du guide redéfinit une
  // partie des mêmes mots, hors de la référence et hors de ce verdict.
  const srcAideTexte = readFileSync(path.join(WEB, "help.js"), "utf8");
  const termesGlossaire = [...srcAideTexte.matchAll(/\{\s*t:\s*'([^']+)'/g)].map((m) => m[1]);
  exiger(termesGlossaire.length > 10, `(38) instrument : ${termesGlossaire.length} terme(s) de glossaire lus — la lecture est cassée`);
  const glossaireCommandes = termesGlossaire.filter((t) => COMMANDES.includes(t));

  console.log(`[gxql-reference] UNE seule référence du langage : le bouton « ? Aide » de la barre de requête et le guide rendent le MÊME texte (${parLaBarre.corps.length} caractères). ${declares.size} jetons DÉCLARÉS par le démon en ${NOMS.length} vocabulaires (${NOMS.map((n) => `${n.replace("DOC_", "").toLowerCase()}=${(parVocabulaire.get(n) || []).length}`).join(", ")}) ; la référence les écrit TOUS, en français comme en anglais, et n'en écrit aucun que la déclaration ne porte pas. Seconde référence : refusée par un critère DÉRIVÉ (nommer >= ${SEUIL} des ${COMMANDES.length} commandes) — ${references.length} surface(s) au-dessus du seuil, toutes « soql », la plus haute des autres étant « ${plusHauteHors[0]} » à ${plusHauteHors[1]}. ${(bornes || []).length} BORNE(S) du langage sont déclarées par le corpus (docs/GXQL.md) et PORTÉES par les trois surfaces qui décrivent la commande — la déclaration du démon (fr) et l'aide rendue (fr et en) : ${(bornes || []).map((x) => `${x.cmd} = « ${x.fr} » / « ${x.en} »`).join(" ; ")}. Ce que ce témoin NE tient PAS : le libellé des descriptions NON bornées par le corpus (${COMMANDES.length - (bornes || []).length} des ${COMMANDES.length} commandes) ; il ne COMPILE rien, la borne elle-même est une mesure DATÉE du corpus, pas un verdict d'ici ; la liste des CHAMPS, déclarée dans le cœur partagé et illisible d'ici ; et le glossaire du guide, qui redéfinit ${glossaireCommandes.length} des ${COMMANDES.length} commandes (${glossaireCommandes.join(", ")}) sans prétendre énumérer le langage — une commande retirée y survivrait sans que ce verdict le voie.`);
}

// ---------------------------------------------------------------------------------------------
// 39. UNE MATRICE ATT&CK VIDE N'EST PAS UNE ABSENCE DE COUVERTURE — ET LA SURFACE NE DOIT NOMMER
//     AUCUNE CAUSE QUE LE DÉMON NE PRODUIT PAS (`P11.6-c`, `P11.6-e`, mesure du 2026-08-26).
//     Le démon empile UNE entrée par tactique du catalogue SANS condition sur les données — son test
//     livré `attack_matrix_empty_rules_all_uncovered` l'exige sur zéro règle et zéro alerte — donc une
//     réponse CALCULÉE n'est jamais vide, et la matrice ne peut pas rendre « aucune tactique ».
//     CE TÉMOIN A ENTÉRINÉ UNE ÉNUMÉRATION FAUSSE, RETIRÉE ICI. Il recopiait dans son verdict VERT les
//     deux causes que le module affirmait (« permis de requête », « chien de garde ») sans jamais LIRE
//     les sorties du démon. Elles sont réfutées, et le témoin lit désormais les deux textes qui les
//     réfutent : `acquire_query_permit` ATTEND sur `NoPermits` (son seul `Err` est le sémaphore FERMÉ),
//     et `read_with_watchdog` ne rend son `default` que si `read_conn_get` échoue — le chien de garde,
//     lui, interrompt la connexion et laisse la closure rendre une matrice PLEINE et sous-comptée.
//     Le témoin tient donc CINQ choses, dans les deux sens et dans les deux langues : une réponse qui
//     porte des tactiques ne dit RIEN ; une réponse vide et MUETTE DIT le refus, DÉMENT l'absence et
//     AVOUE ne pas savoir laquelle des sorties dégradées a joué ; elle NE NOMME PAS une cause que le
//     démon ne produit pas — un `saturated`/`saturé` ou un `watchdog`/`chien de garde` réintroduit dans
//     la phrase servie fait ROUGIR ce témoin ; et une réponse vide qui PORTE la cause du démon la rend
//     TELLE QUELLE, sans avouer une ignorance qu'elle n'a plus.
//     LA CINQUIÈME EST NEUVE, ET ELLE RETIRE UNE IMPOSSIBILITÉ PÉRIMÉE (`P10.7-d`, mesuré le
//     2026-08-29). Ce témoin écrivait, dans son en-tête ET dans son verdict VERT, qu'aucune des trois
//     sorties dégradées ne se distinguait des autres, et qu'il aurait fallu pour cela un marqueur que le
//     démon ne posait pas. La clause périmée n'est pas RECITÉE ici : la reprendre entre guillemets la
//     laisserait s'imprimer à chaque exécution, c'est-à-dire garder le défaut en le commentant.
//     C'est FAUX depuis `P10.7-c` : la sortie du portillon passe par `portillon::corps_de_refus` et pose
//     sa cause sous `error` (`daemon/src/handlers/portillon.rs`), et `coverage_attack` — la route
//     qu'interroge `attack.js` — est l'un de ses appelants. Le marqueur EXISTE pour l'UNE des trois ; le
//     banc affirmait qu'il n'en existait aucun, donc rendait MOINS que ce que le dépôt sait, dans la
//     phrase même où il avoue son ignorance. La clause n'est pas remplacée par une autre clause : les
//     DEUX nombres — combien de sorties dégradées, combien portent la cause — sont DÉRIVÉS du corps de
//     la route, et la voie MARQUÉE est EXERCÉE plutôt qu'affirmée.
//     L'INSTRUMENT SE VALIDE : les propriétés du démon sont LUES dans son arbre, jamais recopiées ici —
//     et la cause elle-même est EXTRAITE du littéral `CAUSE_PORTILLON_CLOS`, jamais retapée, sans quoi
//     ce témoin rejouerait le défaut de citation périmée que `P11.21-a` vient de fermer ailleurs. Si
//     l'une disparaît, le témoin refuse de conclure au lieu de garder une conclusion périmée.
//     CE QU'IL NE TIENT PAS : LAQUELLE des sorties encore MUETTES a joué — celles-là rendent bien le même
//     corps, et seul un marqueur DE PLUS les séparerait ; et la matrice PLEINE et sous-comptée que rend
//     une lecture interrompue — le même défaut sous une forme que le tableau vide ne trahit pas, ouvert
//     sous `P11.6-e`.
// ---------------------------------------------------------------------------------------------
{
  // — instrument : les propriétés qui rendent le verdict possible sont LUES dans le démon.
  const srcMatrice = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "alerts.rs"), "utf8");
  const corps = srcMatrice.match(/fn build_attack_matrix\([\s\S]*?\n\}/);
  exiger(!!corps, "(39) instrument : `build_attack_matrix` introuvable dans le démon — le témoin ne lit plus la propriété qu'il invoque");
  exiger(!!corps && /for tac in guatx_core::attack::TACTICS \{/.test(corps[0]) && /tactics_json\.push\(/.test(corps[0]),
    "(39) instrument : `build_attack_matrix` n'empile plus une entrée par tactique du catalogue sans condition — une réponse calculée POURRAIT être vide, et la phrase de refus deviendrait fausse");
  const srcTest = readFileSync(path.join(RACINE, "daemon", "src", "tests", "rbac.rs"), "utf8");
  exiger(/fn attack_matrix_empty_rules_all_uncovered\(\)[\s\S]*?for tac in guatx_core::attack::TACTICS[\s\S]*?expect\("tactique présente"\)/.test(srcTest),
    "(39) instrument : le test livré qui EXIGE toutes les tactiques sur zéro règle et zéro alerte n'est plus retrouvé — la seule preuve qu'une matrice calculée n'est jamais vide a disparu");
  // — instrument : LES DEUX RÉFUTATIONS. Elles sont la raison d'être de la phrase servie ; si le démon
  //   changeait, la phrase pourrait redevenir nommable et ce témoin doit le voir plutôt que l'ignorer.
  const srcPermis = readFileSync(path.join(RACINE, "daemon", "src", "query_timing.rs"), "utf8");
  const permis = srcPermis.match(/pub\(crate\) async fn acquire_query_permit\([\s\S]*?\n\}/);
  exiger(!!permis
    && /Err\(TryAcquireError::NoPermits\) => \{\}/.test(permis[0])
    && /Err\(TryAcquireError::Closed\) => \{/.test(permis[0])
    && /acquire_owned\(\)\.await\?/.test(permis[0].replace(/\s+/g, "")),
    "(39) instrument : `acquire_query_permit` ne montre plus qu'il ATTEND sur `NoPermits` — la réfutation de « permis saturé » n'est plus lisible dans le démon");
  const srcExec = readFileSync(path.join(RACINE, "daemon", "src", "query_exec.rs"), "utf8");
  const wd = srcExec.match(/pub\(crate\) fn read_with_watchdog<T>\([\s\S]*?\n\}/);
  exiger(!!wd && /read_conn_get\(db_path\) \{ Ok\(c\) => c, Err\(_\) => return default \}/.test(wd[0].replace(/\s+/g, " ")),
    "(39) instrument : `read_with_watchdog` ne rend plus son `default` sur le seul échec de `read_conn_get` — la réfutation de « chien de garde » n'est plus lisible dans le démon");

  // — instrument : LE MARQUEUR QUI EXISTE (`P10.7-c`), et les DEUX NOMBRES qui remplacent l'impossibilité
  //   périmée que ce témoin imprimait. Ils sont DÉRIVÉS du corps de la route, jamais énumérés ici : si
  //   demain une sortie de plus se nomme, le verdict suit sans qu'on le réécrive.
  const routeAttack = srcMatrice.match(/pub\(crate\) async fn coverage_attack\([\s\S]*?\n\}/);
  exiger(!!routeAttack, "(39) instrument : `coverage_attack` introuvable dans le démon — le témoin ne peut plus compter les sorties dégradées de la route qu'`attack.js` interroge");
  const corpsRoute = (routeAttack || [""])[0];
  const FORME_VIDE = /json!\(\{\s*"tactics":\s*\[\],\s*"totals":\s*\{\}\s*\}\)/g;
  const FORME_VIDE_MARQUEE = /corps_de_refus\(\s*json!\(\{\s*"tactics":\s*\[\],\s*"totals":\s*\{\}\s*\}\)\s*\)/g;
  const sortiesDegradees = (corpsRoute.match(FORME_VIDE) || []).length;
  const sortiesMarquees = (corpsRoute.match(FORME_VIDE_MARQUEE) || []).length;
  exiger(sortiesDegradees >= 2 && sortiesMarquees >= 1 && sortiesMarquees <= sortiesDegradees,
    `(39) instrument : ${sortiesDegradees} sortie(s) dégradée(s) et ${sortiesMarquees} marquée(s) lues dans \`coverage_attack\` — le compte est dégénéré, et un verdict qui s'appuierait dessus ne mesurerait rien`);
  const srcPortillon = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "portillon.rs"), "utf8");
  exiger(/corps\["error"\]\s*=\s*json!\(CAUSE_PORTILLON_CLOS\)/.test(srcPortillon),
    "(39) instrument : `corps_de_refus` ne pose plus `CAUSE_PORTILLON_CLOS` sous `error` — la sortie marquée ne l'est plus, et la propriété neuve de ce témoin n'a plus d'objet");
  // La cause est EXTRAITE du littéral Rust — continuations recollées — et JAMAIS retapée : une copie
  // vieillirait en silence, ce qui est exactement le défaut que `P11.21-a` a fermé dans la console.
  const litteralCause = srcPortillon.match(/const CAUSE_PORTILLON_CLOS: &str = "((?:[^"\\]|\\[\s\S])*)"/);
  exiger(!!litteralCause, "(39) instrument : le littéral de `CAUSE_PORTILLON_CLOS` n'est plus lisible — le témoin devrait recopier la cause, et une copie périme sans un mot");
  const CAUSE_DU_DEMON = ((litteralCause || ["", ""])[1] || "").replace(/\\\r?\n\s*/g, "");
  exiger(CAUSE_DU_DEMON.length > 40 && !CAUSE_DU_DEMON.includes("\\"),
    `(39) instrument : la cause extraite du démon fait ${CAUSE_DU_DEMON.length} caractère(s) et porte encore une continuation — le recollement du littéral Rust est faux, et tout ce qui s'appuie dessus jugerait d'un texte inventé`);

  const SUF = "?plume-lang=en";
  const urlM = (f, suffixe = "") => pathToFileURL(path.join(WEB, f)).href + suffixe;
  const { refusDeMatrice: refusFR } = await import(urlM("attack.js"));
  localStorage.setItem("soc_lang", "en");
  const { refusDeMatrice: refusEN } = await import(urlM("attack.js", SUF));
  localStorage.removeItem("soc_lang");

  // — sens POSITIF : une réponse qui porte des tactiques ne prononce aucun refus.
  const servie = { tactics: [{ tactic: "discovery", techniques: [{ tid: "T1046", name: "Network Service Discovery", covered: true, rule_count: 1, alert_count: 0 }] }], totals: {} };
  exiger(refusFR(servie) === null && refusEN(servie) === null, `(39) une matrice SERVIE est prise pour un refus : « ${refusFR(servie)} »`);

  // — sens NÉGATIF : la forme dégradée du démon, et deux corps qui n'en viennent pas.
  for (const [quoi, d] of [["la forme dégradée du démon", { tactics: [], totals: {} }], ["un corps sans clé `tactics`", { totals: {} }], ["une réponse informe", null]]) {
    for (const [langue, refus] of [["fr", refusFR], ["en", refusEN]]) {
      const m = refus(d);
      exiger(typeof m === "string" && m.trim().length > 0, `(39) ${quoi} sous LANG='${langue}' : la surface ne dit RIEN (« ${m} ») — un refus tu se lit comme un vide`);
      // « ne contient pas le mot absence » ne serait pas une propriété : la phrase EXPLIQUE le vide, donc
      // elle le nomme. Ce qui est décidable, et c'est ce qui compte, c'est qu'elle NOMME le refus et qu'elle
      // DÉMENTE la lecture « il n'y a pas de couverture ». L'ancien texte (« aucune tactique dans la matrice
      // de couverture. ») échoue aux deux : il ne nomme aucun refus et ne dément rien.
      exiger(/refus|décliné|declined|refused/i.test(m), `(39) ${quoi} sous LANG='${langue}' : le texte ne NOMME pas le refus (« ${m} »)`);
      exiger(/pas une absence|not an absence/i.test(m), `(39) ${quoi} sous LANG='${langue}' : le texte ne DÉMENT pas la lecture « aucune couverture » (« ${m} ») — un refus qui ne se distingue pas d'un vide se lit comme un vide`);
      // LA PROPRIÉTÉ NEUVE DU 2026-08-26, dans les deux sens. (a) le texte AVOUE son ignorance…
      exiger(/\bne (peut|sait)\b.{0,20}?\bpas\b|cannot (say|tell)/i.test(m), `(39) ${quoi} sous LANG='${langue}' : le texte n'AVOUE pas ce qu'il ignore (« ${m} ») — il tranche une cause que la réponse ne porte pas`);
      // …(b) et il ne NOMME aucune des deux causes que la lecture du démon a réfutées.
      exiger(!/satur|watchdog|chien de garde/i.test(m), `(39) ${quoi} sous LANG='${langue}' : le texte nomme une cause que le démon NE PRODUIT PAS (« ${m} ») — la saturation attend, et le chien de garde rend une matrice pleine`);
    }
  }
  // — LA VOIE MARQUÉE, EXERCÉE PLUTÔT QU'AFFIRMÉE. Un corps qui PORTE la cause du démon la rend telle
  //   quelle, et il ne se confond plus avec le corps muet : c'est cela, et cela seul, qui rend dicible
  //   la clause neuve du verdict. Le sens NÉGATIF est le dernier `exiger` : un texte qui avouerait
  //   quand même son ignorance rendrait MOINS que ce que la réponse porte.
  for (const [langue, refus] of [["fr", refusFR], ["en", refusEN]]) {
    const m = refus({ tactics: [], totals: {}, error: CAUSE_DU_DEMON });
    const muet = refus({ tactics: [], totals: {} });
    exiger(typeof m === "string" && m.includes(CAUSE_DU_DEMON), `(39) corps MARQUÉ sous LANG='${langue}' : la cause SERVIE par le démon n'est pas rendue à l'analyste (« ${m} ») — le marqueur existe et la surface le jette`);
    exiger(/refus|décliné|declined|refused/i.test(m), `(39) corps MARQUÉ sous LANG='${langue}' : le texte ne NOMME pas le refus (« ${m} »)`);
    exiger(/pas une absence|not an absence/i.test(m), `(39) corps MARQUÉ sous LANG='${langue}' : le texte ne DÉMENT pas la lecture « aucune couverture » (« ${m} »)`);
    exiger(m !== muet, `(39) corps MARQUÉ sous LANG='${langue}' : la surface rend la MÊME phrase avec et sans la cause — le marqueur du démon n'atteint pas l'analyste, et les sorties dégradées restent indiscernables`);
    exiger(!/\bne (peut|sait)\b.{0,20}?\bpas\b|cannot (say|tell)/i.test(m.replace(CAUSE_DU_DEMON, "")), `(39) corps MARQUÉ sous LANG='${langue}' : le texte AVOUE une ignorance qu'il n'a PLUS (« ${m} ») — la cause est servie, la taire rend moins que ce qui est su`);
  }
  exiger(refusFR({ tactics: [], totals: {} }) !== refusEN({ tactics: [], totals: {} }), "(39) le refus rend le même texte dans les deux langues : une des deux n'est pas écrite");
  // Deux corps de PROVENANCE différente ne reçoivent pas la même phrase : celle du corps informe n'impute
  // rien au démon, faute de pouvoir le prouver.
  exiger(refusFR({ tactics: [], totals: {} }) !== refusFR({ totals: {} }), "(39) un corps qui n'est pas de cette route reçoit la phrase des sorties dégradées du démon — c'est imputer sans preuve");

  console.log(`[attack-refus] la matrice ne prononce plus d'absence sur un tableau vide, ET ne nomme plus de cause que le démon ne produit pas : sur 3 formes de réponse (forme dégradée du démon, corps sans clé, réponse informe) et dans les deux langues, le texte NOMME le refus, DÉMENT l'absence, AVOUE ce qu'il ignore, et ne prononce ni « saturé » ni « chien de garde » — deux causes que la lecture du démon RÉFUTE (la saturation ATTEND, seul le sémaphore FERMÉ rend une erreur ; le chien de garde interrompt la connexion et laisse rendre une matrice PLEINE). Les deux corps qui ne viennent pas de cette route reçoivent une phrase distincte, qui n'impute rien au démon. Quatre propriétés du démon sont LUES dans son arbre — boucle inconditionnelle sur les tactiques, test livré sur zéro règle, attente sur NoPermits, un repli réservé à l'échec de connexion — et le témoin refuse de conclure si l'une disparaît. UNE DES SORTIES SE NOMME DÉSORMAIS, ET LE BANC CESSE D'IMPRIMER LE CONTRAIRE (\`P10.7-d\`, mesuré le 2026-08-29) : sur les ${sortiesDegradees} sorties dégradées LUES dans \`coverage_attack\`, ${sortiesMarquees} passe par \`portillon::corps_de_refus\` et pose sa cause sous \`error\` depuis \`P10.7-c\` — ce verdict imprimait qu'aucun marqueur n'existait et qu'il en aurait fallu un pour séparer les trois sorties, alors que le dépôt l'avait DÉJÀ posé. La cause est EXTRAITE de \`CAUSE_PORTILLON_CLOS\` (${CAUSE_DU_DEMON.length} caractères, jamais retapée ici) et la surface la rend TELLE QUELLE dans les deux langues, sans avouer une ignorance qu'elle n'a plus. Ce qu'il NE tient PAS : LAQUELLE des ${sortiesDegradees - sortiesMarquees} sorties encore MUETTES a joué (celles-là rendent le même corps, seul un marqueur DE PLUS les séparerait) ; et la matrice PLEINE et SOUS-COMPTÉE que rend une lecture interrompue — même défaut, forme que le tableau vide ne trahit pas, ouvert sous \`P11.6-e\`.`);
}

// ---------------------------------------------------------------------------------------------
// 40. LES SEPT LISTES QUI RESTAIENT SANS MÉMOIRE LA PORTENT MAINTENANT, ET SUR LEUR PROPRE CHEMIN
//     DE VUE (`P11.18-z`).
//     CE QUE LE TÉMOIN 37 NE POUVAIT PAS DIRE. Il exerce la FABRIQUE sur une liste construite pour lui,
//     à qui IL donne une identité : il prouve le mécanisme, pas son ARMEMENT. Mesuré le 2026-08-26 par
//     dérivation sur `web/` : une seule des huit listes cherchables du produit déclarait une identité
//     (`detection_admin.js`, qui en portait déjà une pour son pli), et aucune des trois vues que le
//     constat nomme. Ce témoin-ci part des MODULES RÉELS et de leurs propres chargeurs de vue.
//     (a) L'INSTRUMENT D'ABORD : chaque vue est rendue par SON chargeur sur une charge utile fabriquée,
//         et le témoin épingle le nombre de lignes rendues avant toute recherche. Sans ce compte, un
//         « rien n'a changé » se lirait comme un succès.
//     (b) LES SEPT SURFACES, une par une : la recherche frappée filtre ; le chargeur de la vue est
//         rappelé — c'est la DERNIÈRE instruction de chacun des gestes éditoriaux de ces vues — l'hôte de
//         la liste est REFABRIQUÉ (le témoin épingle que le champ n'est pas le même objet, sans quoi il ne
//         reconstituerait pas un rechargement), la recherche est reposée ET appliquée ; puis, vidée, elle
//         ne renaît pas au rechargement suivant.
//     (c) LE CHEMIN COMPLET, DEPUIS LE BOUTON DE LA LIGNE, sur trois modules et deux confirmations
//         partagées différentes : retirer la déclaration d'un hôte, lever un silence, révoquer un jeton.
//         Le témoin clique le bouton de la LIGNE, valide la fenêtre, et la charge utile SERVIE change —
//         donc ce qui revient n'est pas une peinture rejouée. La recherche, elle, tient.
//     (d) DEUX LISTES D'UN MÊME ÉCRAN NE PARTAGENT PAS LEUR MÉMOIRE. Les trois listes du panneau
//         Suppressions sont rechargées par le MÊME `loadSuppressions()` : une recherche frappée dans les
//         silences ne doit reparaître ni dans le registre du démon, ni chez les collecteurs — une
//         recherche appliquée à la mauvaise liste est pire que pas de mémoire du tout.
//     CE QUE CE TÉMOIN NE TIENT PAS, ET IL L'ÉCRIT : il ne joue pas les onze autres gestes éditoriaux de
//     ces vues (éditer une source, déclarer une cadence, réinitialiser une exclusion, créer un jeton…) —
//     il rappelle leur chargeur, qui est leur dernière instruction ; il ne dit rien de la mise en page ni
//     du style ; et il ne prouve rien du panneau Risque comme vue ÉDITORIALE, qui ne porte aucun geste
//     d'écriture (sa mémoire sert le rafraîchissement et le retour au panneau, exercés en (b)).
// ---------------------------------------------------------------------------------------------
{
  const modFleet = await import(pathToFileURL(path.join(WEB, "fleet.js")).href);
  const modSources = await import(pathToFileURL(path.join(WEB, "sources.js")).href);
  const modSupp = await import(pathToFileURL(path.join(WEB, "suppressions.js")).href);
  const modAdmin = await import(pathToFileURL(path.join(WEB, "admin_users.js")).href);
  const modRisk = await import(pathToFileURL(path.join(WEB, "risk.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);

  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const lignesDe = (h) => cueillir(h, (e) => e.tagName === "TR", []).filter((tr) => cueillir(tr, (e) => e.tagName === "TD", []).length > 0);
  // UNE LISTE = SON CHAMP ET L'HÔTE QUI LE PORTE, APPARIÉS PAR LE PARENT — jamais par une position dans
  // l'écran : la fabrique pose [barre, avis?, résumé, corps] dans l'hôte, et le champ vit dans la barre.
  // Un panneau qui gagnerait ou perdrait une section décalerait un repérage positionnel sans rien dire.
  const listesDe = (racine) => cueillir(racine, (e) => e.tagName === "INPUT" && e.type === "search", [])
    .map((champ) => { const hote = champ.parentNode && champ.parentNode.parentNode; return { champ, hote, lignes: () => lignesDe(hote) }; })
    .filter((l) => !!l.hote);
  const laListeQuiPorte = (racine, marqueur) => listesDe(racine).find((l) => String(l.hote.textContent).includes(marqueur)) || null;
  const frapper = (liste, texte) => { liste.champ.value = texte; liste.champ.dispatchEvent({ type: "input" }); };
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const attendre = async (n = 25) => { for (let i = 0; i < n; i++) await tick(); };
  const derniereFenetre = () => document.body.children.filter((c) => c.classList && c.classList.contains("modal-ov")).pop();
  const validerLaFenetre = () => { const ov = derniereFenetre(); if (!ov || !ov.children[0] || !ov.children[0].children[0]) return false; ov.children[0].children[0].onsubmit({ preventDefault() {} }); return true; };
  const boutonDeLaLigne = (tr, re) => cueillir(tr, (e) => e.tagName === "BUTTON" && re.test(e.title || ""), [])[0] || null;

  // LES CHARGES UTILES SONT MUTABLES, et c'est ce qui rend le geste ÉDITORIAL : une écriture change ce que
  // la route SERT ensuite, donc la liste qui revient n'est pas la peinture d'avant rejouée.
  const etat = {
    fleet: { pipeline_fresh: true, now: 1000, hosts: [
      { host: "web-01", status: "silent", last_seen: 100, signals: 12, first_seen: 10, enrolled: false, attente: "silence_attendu", declaree_par: "l'exploitant", attente_libelle: "banc de test — déclaré par l'exploitant" },
      { host: "web-02", status: "fresh", last_seen: 990, signals: 40, first_seen: 10, enrolled: false, attente: "non_declare" },
      { host: "db-01", status: "fresh", last_seen: 980, signals: 33, first_seen: 10, enrolled: false, attente: "non_declare" },
    ] },
    sources: { pipeline_fresh: true, sources: [
      { source: "sshd-session", status: "frais", expected: true, declaree_par: "ce dépôt", last_seen: 990, age_s: 10, n_24h: 42, unexpected: false, in_collectors: true },
      { source: "sshd-auth", status: "calme", expected: true, declaree_par: "ce dépôt", last_seen: 980, age_s: 20, n_24h: 12, unexpected: false, in_collectors: true },
      { source: "ufw", status: "frais", expected: false, last_seen: 970, age_s: 30, n_24h: 7, unexpected: true },
    ] },
    suppressions: { generated: 1000, firewall: null, firewall_n_hosts: 0, daemon: [
      { name: "A1_operator_self", label: "exclusion opérateur", type: "display-only", value: "root", scope: "affichage", source: "core/display.rs", editable: true },
      { name: "A2_ufw_noise", label: "bruit ufw", type: "display-only", value: "ufw", scope: "affichage", source: "core/display.rs", editable: true },
      { name: "A3_kernel_drop", label: "kernel drop", type: "collection-reducing", value: "kern", scope: "ingestion", source: "core/ingest.rs", editable: false },
    ], collectors: [
      { source: "sshd", type: "display-only", fields: { filters: { exclude: ["debug"] } }, ts: 990, host: "web-01", attested: true },
      { source: "ufw", type: "display-only", fields: { filters: { exclude: ["accept"] } }, ts: 980, host: "web-02", attested: true },
      { source: "auditd", type: "collection-reducing", fields: { filters: { exclude: ["bruit"] } }, ts: 970, host: "db-01", attested: true },
    ] },
    silences: { silences: [
      { id: 1, matchers: { rule: "web.brute" }, active: true, expires_at: 2000, reason: "maintenance planifiée", created_by: "hugo" },
      { id: 2, matchers: { rule: "ssh.brute" }, active: true, expires_at: 2000, reason: "bruit connu", created_by: "hugo" },
      { id: 3, matchers: { host: "db-01" }, active: false, expires_at: 500, reason: "migration", created_by: "hugo" },
    ] },
    tokens: { tokens: [
      { name: "agent-web-01", kind: "agent", host: "web-01", created: 100, last_used: 900 },
      { name: "agent-web-02", kind: "agent", host: "web-02", created: 200, last_used: 900 },
      { name: "hec-forwarder", kind: "hec", host: "", created: 300, last_used: 0 },
    ] },
    risk: { served: 3, total: 3, total_capped: false, window: 86400, over_threshold_total: 1,
      thresholds: { score: 50, distinct_tactics: 3, velocity: 5, window_s: 86400 }, entities: [
      { entity_type: "host", entity: "web-01", score: 61, score_hot: 12, contrib: 4, distinct_tactics: 2, tactics: "TA0006, TA0008", max_severity: 4, first_ts: 100, last_ts: 990, over_threshold: true },
      { entity_type: "host", entity: "web-02", score: 22, score_hot: 3, contrib: 2, distinct_tactics: 1, tactics: "TA0006", max_severity: 3, first_ts: 100, last_ts: 980, over_threshold: false },
      { entity_type: "user", entity: "compte-de-service", score: 9, score_hot: 0, contrib: 1, distinct_tactics: 1, tactics: "TA0001", max_severity: 2, first_ts: 100, last_ts: 970, over_threshold: false },
    ] },
  };
  const routes = [["/api/risk/entities", () => etat.risk], ["/api/fleet", () => etat.fleet], ["/api/sources", () => etat.sources],
    ["/api/suppressions", () => etat.suppressions], ["/api/silences", () => etat.silences], ["/api/tokens", () => etat.tokens]];
  const ecritures = [];
  const hotes = { "#fleet-body": new Element("div"), "#sources-body": new Element("div"), "#suppressions-body": new Element("div"), "#token-list": new Element("div"), "#risk-list": new Element("div") };

  const qsOrigine = document.querySelector, fetchOrigine = globalThis.fetch;
  const etatOrigine = { auth: S.AUTH, admin: S.isAdmin };
  document.querySelector = (sel) => hotes[sel] || new Element("div");
  globalThis.fetch = async (u, o) => {
    const url = String(u), methode = (o && o.method) || "GET";
    if (methode !== "GET") {
      ecritures.push(methode + " " + url);
      if (/\/api\/hosts\/settings/.test(url)) etat.fleet = { ...etat.fleet, hosts: etat.fleet.hosts.map((h) => (h.host === "web-01" ? { ...h, attente: "non_declare", declaree_par: "", attente_libelle: "" } : h)) };
      if (/\/api\/silences\//.test(url)) etat.silences = { silences: etat.silences.silences.filter((s) => s.id !== 1) };
      if (/\/api\/tokens\//.test(url)) etat.tokens = { tokens: etat.tokens.tokens.filter((t) => t.name !== "agent-web-01") };
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true }) };
    }
    for (const [frag, charge] of routes) if (url.includes(frag)) return { ok: true, status: 200, text: async () => JSON.stringify(charge()) };
    return { ok: true, status: 200, text: async () => JSON.stringify({}) };
  };
  try {
    S.AUTH = { user: "hugo", role: "admin" }; S.isAdmin = true;

    // (a) + (b) LES SEPT SURFACES, PAR LEUR PROPRE CHARGEUR DE VUE.
    const surfaces = [
      { nom: "flotte", cle: "soc_fleet_hosts", hote: "#fleet-body", charger: () => modFleet.loadFleetView(), marqueur: "web-01", mot: "web", avant: 3, apres: 2 },
      { nom: "inventaire des sources", cle: "soc_sources_inventory", hote: "#sources-body", charger: () => modSources.loadSourcesView(), marqueur: "sshd-session", mot: "sshd", avant: 3, apres: 2 },
      { nom: "jetons d'agent", cle: "soc_admin_tokens", hote: "#token-list", charger: () => modAdmin.loadTokens(), marqueur: "agent-web-01", mot: "agent-web", avant: 3, apres: 2 },
      { nom: "risque par entité", cle: "soc_risk_entities", hote: "#risk-list", charger: () => modRisk.loadRiskView(), marqueur: "web-01", mot: "web", avant: 3, apres: 2 },
      { nom: "silences d'alertes", cle: "soc_silences", hote: "#suppressions-body", charger: () => modSupp.loadSuppressions(), marqueur: "web.brute", mot: "brute", avant: 3, apres: 2 },
      { nom: "registre du démon", cle: "soc_daemon_suppressions", hote: "#suppressions-body", charger: () => modSupp.loadSuppressions(), marqueur: "kernel drop", mot: "kern", avant: 3, apres: 1 },
      { nom: "collecteurs hôte", cle: "soc_collector_suppressions", hote: "#suppressions-body", charger: () => modSupp.loadSuppressions(), marqueur: "auditd", mot: "auditd", avant: 3, apres: 1 },
    ];
    for (const s of surfaces) {
      const racine = hotes[s.hote];
      await s.charger(); await attendre(6);
      const l1 = laListeQuiPorte(racine, s.marqueur);
      exiger(!!l1, `(40a) ${s.nom} : aucune liste cherchable ne porte « ${s.marqueur} » après le chargement de la vue — le témoin ne mesure rien`);
      if (!l1) continue;
      exiger(l1.lignes().length === s.avant, `(40a) instrument : ${s.nom} rend ${l1.lignes().length} ligne(s) au lieu de ${s.avant} avant toute recherche`);
      frapper(l1, s.mot);
      exiger(l1.lignes().length === s.apres, `(40b) instrument : ${s.nom} — « ${s.mot} » rend ${l1.lignes().length} ligne(s) au lieu de ${s.apres} : la recherche ne filtre pas cette liste`);
      await s.charger(); await attendre(6);
      const l2 = laListeQuiPorte(racine, s.marqueur);
      exiger(!!l2 && l2.champ !== l1.champ, `(40b) instrument : ${s.nom} — le rechargement de la vue REND LE MÊME champ ; il ne reconstitue pas un rendu qui détruit son hôte, et rien de ce qui suit ne prouverait quoi que ce soit`);
      if (!l2) continue;
      exiger(l2.champ.value === s.mot, `(40b) ${s.nom} (identité \`${s.cle}\`) : la recherche n'a pas survécu au rechargement de la vue — champ « ${l2.champ.value} » au lieu de « ${s.mot} »`);
      exiger(l2.lignes().length === s.apres, `(40b) ${s.nom} : la recherche est reposée dans le champ mais la liste rend ${l2.lignes().length} ligne(s) au lieu de ${s.apres} — le champ dit une chose, la liste une autre`);
      frapper(l2, "");
      await s.charger(); await attendre(6);
      const l3 = laListeQuiPorte(racine, s.marqueur);
      exiger(!!l3 && l3.champ.value === "" && l3.lignes().length === s.avant, `(40b) ${s.nom} : une recherche VIDÉE renaît au rechargement suivant (« ${l3 && l3.champ.value} », ${l3 && l3.lignes().length} lignes) — le souvenir survit au geste qui l'efface`);
    }

    // (c) LE CHEMIN COMPLET : le bouton de la LIGNE, la fenêtre de confirmation, l'écriture, le retour.
    const gestes = [
      { nom: "retirer la déclaration d'un hôte", hote: "#fleet-body", charger: () => modFleet.loadFleetView(), marqueur: "web-01", mot: "web",
        ligne: "web-01", bouton: /Retirer la déclaration/, apres: 2, ecriture: /PUT \/api\/hosts\/settings/, preuve: (t) => /personne n'a rien dit/.test(t), quoiDeChange: "la déclaration de « web-01 » a disparu de la ligne" },
      { nom: "lever un silence", hote: "#suppressions-body", charger: () => modSupp.loadSuppressions(), marqueur: "ssh.brute", mot: "brute",
        ligne: "web.brute", bouton: /Lever le silence/, apres: 1, ecriture: /DELETE \/api\/silences\/1/, preuve: (t) => !/web\.brute/.test(t), quoiDeChange: "la ligne « rule=web.brute » n'est plus servie" },
      { nom: "révoquer un jeton", hote: "#token-list", charger: () => modAdmin.loadTokens(), marqueur: "agent-web-02", mot: "agent-web",
        ligne: "agent-web-01", bouton: /Révoquer le jeton/, apres: 1, ecriture: /DELETE \/api\/tokens\/agent-web-01/, preuve: (t) => !/agent-web-01/.test(t), quoiDeChange: "le jeton « agent-web-01 » n'est plus servi" },
    ];
    for (const g of gestes) {
      const racine = hotes[g.hote];
      await g.charger(); await attendre(6);
      const avant = laListeQuiPorte(racine, g.marqueur);
      exiger(!!avant, `(40c) ${g.nom} : la liste à exercer n'est pas rendue`);
      if (!avant) continue;
      frapper(avant, g.mot);
      const tr = avant.lignes().find((r) => String(r.textContent).includes(g.ligne));
      const btn = tr ? boutonDeLaLigne(tr, g.bouton) : null;
      exiger(!!btn, `(40c) ${g.nom} : la ligne « ${g.ligne} » n'offre aucun bouton dont le survol dit ${g.bouton} — le geste éditorial n'est pas atteignable depuis la liste, et le chemin mesuré ici serait fictif`);
      if (!btn) continue;
      const nEcrituresAvant = ecritures.length;
      btn.onclick({ stopPropagation() {} });
      await attendre(3);
      exiger(validerLaFenetre(), `(40c) ${g.nom} : aucune fenêtre de confirmation partagée n'a été posée par le geste`);
      await attendre(30);
      // `P11.22-a` — CE TÉMOIN AFFIRME SUR CE QUE SON GESTE A PRODUIT, PAS SUR UN JOURNAL PARTAGÉ.
      // Il exigeait que l'écriture attendue soit la DERNIÈRE du journal global. Or le magasin de
      // préférences programme un envoi DIFFÉRÉ de 800 ms (web/prefs.js) : sur une machine lente il
      // tombe DANS la fenêtre d'observation et prend la dernière place. Mesuré : la chaîne publique a
      // rougi le 2026-08-28 avec `["PUT /api/hosts/settings","PUT /api/prefs"]` — l'écriture attendue
      // était bien partie, elle n'était simplement plus la dernière. Être la dernière n'a JAMAIS été la
      // propriété : la propriété est que le geste éditorial émet son écriture, UNE fois.
      // LA REFORMULATION EST PLUS STRICTE, PAS PLUS LÂCHE : la tranche est celle du geste, et l'unicité
      // y interdit un double envoi que « la dernière » laissait passer.
      const depuisLeGeste = ecritures.slice(nEcrituresAvant);
      const correspondantes = depuisLeGeste.filter((e) => g.ecriture.test(e));
      exiger(correspondantes.length === 1, `(40c) ${g.nom} : le geste doit émettre son écriture EXACTEMENT une fois, vu ${correspondantes.length} (tranche : ${JSON.stringify(depuisLeGeste)})`);
      const apres = laListeQuiPorte(racine, g.marqueur);
      exiger(!!apres && apres.champ !== avant.champ, `(40c) instrument : ${g.nom} — la vue n'a pas été refabriquée après le geste (même champ), le témoin ne mesure pas un rechargement`);
      if (!apres) continue;
      exiger(apres.champ.value === g.mot, `(40c) ${g.nom} : la recherche de l'exploitant a été PERDUE par le geste éditorial — champ « ${apres.champ.value} » au lieu de « ${g.mot} »`);
      exiger(apres.lignes().length === g.apres, `(40c) ${g.nom} : ${apres.lignes().length} ligne(s) rendues au lieu de ${g.apres} — la liste filtrée qui revient ne suit pas ce que la route sert`);
      exiger(g.preuve(String(apres.hote.textContent)), `(40c) instrument : ${g.nom} — ${g.quoiDeChange} n'est pas visible dans la liste revenue : ce qui est peint est l'ancien rendu, et la « survie » de la recherche ne prouverait rien`);
      frapper(apres, "");
    }

    // (d) TROIS LISTES, UN SEUL CHARGEUR, TROIS MÉMOIRES.
    await modSupp.loadSuppressions(); await attendre(6);
    const racineSupp = hotes["#suppressions-body"];
    const silences = laListeQuiPorte(racineSupp, "ssh.brute");
    exiger(!!silences, "(40d) instrument : la liste des silences n'est pas rendue, la mesure de partage n'a pas d'objet");
    if (silences) {
      frapper(silences, "ssh");
      await modSupp.loadSuppressions(); await attendre(6);
      const s2 = laListeQuiPorte(racineSupp, "ssh.brute");
      exiger(!!s2 && s2.champ.value === "ssh", `(40d) instrument : la recherche des silences n'a pas tenu (« ${s2 && s2.champ.value} »), le partage ne se mesure pas`);
      // UNE VOISINE QUI NE MONTRE PLUS SON PROPRE REPÈRE EST DÉJÀ LA RÉPONSE : elle a été filtrée par une
      // recherche qui n'est pas la sienne. Le témoin le DIT ainsi, plutôt que de rendre « null » sous une
      // phrase qui parlerait d'un champ — un instrument qui nomme mal ce qu'il voit se relit de travers.
      for (const [repere, nom] of [["kernel drop", "le registre du démon"], ["auditd", "la liste des collecteurs"]]) {
        const voisine = laListeQuiPorte(racineSupp, repere);
        exiger(!!voisine, `(40d) ${nom} ne montre plus « ${repere} » après une recherche frappée dans les SILENCES : elle est filtrée par une recherche qui n'est pas la sienne, donc les deux listes partagent une identité`);
        if (!voisine) continue;
        exiger(voisine.champ.value === "", `(40d) ${nom} a HÉRITÉ de la recherche des silences (« ${voisine.champ.value} ») : deux listes d'un même écran partagent une identité`);
        exiger(voisine.lignes().length === 3, `(40d) ${nom} rend ${voisine.lignes().length} ligne(s) au lieu de 3 : elle est filtrée par une recherche qui n'est pas la sienne`);
      }
      if (s2) frapper(s2, "");
    }

    // (e) DONNER UNE IDENTITÉ À UNE LISTE N'ÉCRIT RIEN SUR LE POSTE. La clé de rangement d'une liste
    //     GROUPÉE est AUSSI une clé de `localStorage` — c'est là que son pli est persisté. Les sept
    //     listes armées ici ne sont pas groupées, et la mémoire de recherche vit dans une table de
    //     module : une recherche d'exploitant porte un nom de machine, une adresse, un compte, et la
    //     déposer sur le poste la laisserait bien après la session. Les clés jugées sont DÉRIVÉES du
    //     source (identités de TÊTE = toutes celles déclarées, moins celles qui viennent d'un `group`),
    //     et la dérivation est appariée à ce que (b) vient d'exercer avant de servir.
    const clesDuPoste = () => { const t = []; for (let i = 0; i < localStorage.length; i++) t.push(localStorage.key(i)); return t; };
    localStorage.setItem("temoin_p1118z_ecriture", "1");
    exiger(clesDuPoste().includes("temoin_p1118z_ecriture"), "(40e) instrument : la lecture des clés du poste ne voit pas une clé qui vient d'y être posée — ce qui suit ne prouverait rien");
    localStorage.removeItem("temoin_p1118z_ecriture");
    const sourceDesVues = ["fleet.js", "sources.js", "suppressions.js", "admin_users.js", "risk.js", "detection_admin.js"]
      .map((f) => readFileSync(path.join(WEB, f), "utf8")).join("\n");
    const duGroupe = [...sourceDesVues.matchAll(/group:\s*\{\s*storeKey:\s*'([^']+)'/g)].map((m) => m[1]);
    const deTete = [...sourceDesVues.matchAll(/storeKey:\s*'([^']+)'/g)].map((m) => m[1]).filter((k) => !duGroupe.includes(k));
    for (const cle of surfaces.map((s) => s.cle).filter((c) => !duGroupe.includes(c))) {
      exiger(deTete.includes(cle), `(40e) instrument : l'identité « ${cle} » exercée plus haut n'est pas lue dans le source comme une identité de TÊTE — la dérivation qui suit ne porte pas sur ce qui vient d'être exercé`);
    }
    const deposees = clesDuPoste().filter((k) => deTete.includes(k));
    exiger(deposees.length === 0, `(40e) l'identité d'une liste a été DÉPOSÉE sur le poste (${deposees.join(", ")}) : la mémoire de recherche est une table de module qui meurt avec la page, elle n'écrit rien — une recherche porte un nom de machine, une adresse, un compte`);
  } finally {
    document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine;
    S.AUTH = etatOrigine.auth; S.isAdmin = etatOrigine.admin;
  }

  console.log(`[recherche-armee] les SEPT listes cherchables qui n'avaient aucune identité en portent une, et la mémoire de P11.18-z est exercée sur les MODULES RÉELS par leurs propres chargeurs de vue : flotte, inventaire des sources, jetons, risque par entité, silences, registre du démon, collecteurs hôte. Sur trois d'entre elles le chemin part du BOUTON de la ligne, passe par la fenêtre de confirmation partagée, écrit (la charge utile servie CHANGE — déclaration retirée, silence levé, jeton révoqué) et revient : la recherche de l'exploitant tient, la liste revenue suit ce que la route sert, et une recherche vidée ne renaît pas. Les trois listes du panneau Suppressions, rechargées par un SEUL chargeur, ne se passent pas leur recherche. Ce que ce témoin NE tient PAS : les onze autres gestes éditoriaux de ces vues (leur dernière instruction est le chargeur, rappelé ici, mais leur fenêtre n'est pas jouée), rien de la mise en page ni du style, et rien d'une vue sans geste d'écriture au-delà de son rechargement.`);
}

// ---------------------------------------------------------------------------------------------
// 46. UN RÉGLAGE D'AXES QUI ÉCARTE LE LECTEUR DU PANNEAU ENREGISTRÉ LE DIT — ET NE LE DIT QUE LÀ
//     (`P11.18-q`).
//     CE QUE LE TÉMOIN DOIT ÉTABLIR. Le réglage des axes est rangé dans le magasin de préférences, qui
//     est PAR COMPTE : deux exploitants devant le même panneau partagé peuvent voir deux graphes.
//     `P11.18-q` a tranché du côté de la PERSONNE — le panneau n'a aucune fente où loger un axe — et
//     exige alors que la vue DISE que ce qu'elle montre est un réglage privé.
//     (a) L'INSTRUMENT D'ABORD, ET SON CONTRÔLE POSITIF : sans réglage, la vue ne dit rien et rend
//         EXACTEMENT l'appel `vizElement` d'origine (empreinte épinglée) ; avec un réglage qui déplace
//         une colonne, cette empreinte CHANGE. Sans ce second point, « l'aveu est apparu » ne prouverait
//         pas que le lecteur voit autre chose que les autres.
//     (b) L'AVEU EST DÉRIVÉ DE LA DIVERGENCE, PAS DE L'EXISTENCE D'UN RÉGLAGE — et c'est une MUTATION
//         qui le prouve : un réglage qui REDONNE l'ordre par défaut (première colonne en abscisse,
//         dernière en ordonnée) ne fait apparaître AUCUN aveu, et rend une empreinte byte-identique à
//         celle sans réglage. Un aveu qui parlerait dès qu'un réglage existe crierait au loup.
//     (c) L'AVEU NOMME CE QUE LES AUTRES VOIENT, et il le tient de la REPRÉSENTATION : sur le même
//         réglage, `bar` (qui ne lit pas la fente du milieu) nomme deux colonnes, `heatmap` (qui la lit)
//         en nomme trois. Une phrase écrite en dur ne pourrait pas faire cette différence.
//     (d) UN CHOIX IMPOSSIBLE reste un refus, ET l'aveu l'accompagne : le lecteur voit un texte là où
//         les autres voient un graphe, ce qui est la divergence la plus forte de toutes.
//     (e) SANS IDENTITÉ DE PANNEAU, RIEN N'EST DÉCLARÉ : il n'existe alors aucun panneau enregistré dont
//         on pourrait s'écarter. Ce n'est pas un silence, c'est une absence d'objet — et le témoin
//         l'épingle pour que ce silence ne s'étende jamais au cas qui a une identité.
//     (f) LES DEUX LANGUES, par une seconde instance du graphe sous `LANG='en'`.
//     (g) LA PHRASE DIT « l'instantané partageable ne les emporte pas » — une garde DIT ce qu'elle ne
//         tient pas, et ce qu'elle dit doit être VRAI. C'est DÉRIVÉ du source : le corps de
//         `captureSnapshot` rend ses panneaux par `vizElement`, le chemin SANS réglage, et n'appelle
//         jamais la fabrique réglée. Le jour où il l'appellerait, cette phrase deviendrait fausse et ce
//         témoin rougit avant elle.
//     CE QUE CE TÉMOIN NE TIENT PAS : ni la mise en page ni le style calculé (l'aveu porte la classe
//     partagée `rf-hint`, ce banc ne sait pas s'il est LU) ; ni ce que voit l'AUTRE compte — le banc n'a
//     qu'une identité, et c'est le magasin de préférences, mesuré ailleurs, qui est par compte ; ni la
//     capture serveur de l'instantané, qui ne porte aucun champ d'axe (mesuré dans le démon, pas ici).
// ---------------------------------------------------------------------------------------------
{
  const SUF41 = "?plume-lang=en";
  const url41 = (f, sfx = "") => pathToFileURL(path.join(WEB, f)).href + sfx;
  const vizFR = await import(url41("viz.js"));
  const prefsFR = await import(url41("prefs.js"));

  const COLS = ["host", "source", "count"];
  const ROWS = [["web-01", "sshd", 12], ["db-01", "ufw", 7], ["web-02", "sshd", 3]];
  const PANNEAU = 4141;
  const CLE_PANNEAU = "p" + PANNEAU;
  const CLE_SANS_PANNEAU = "c" + COLS.join("\x1f");
  // L'AVEU est le seul `rf-hint` NU : le refus, lui, porte `rf-hint bad`. Les distinguer par la classe
  // plutôt que par la position évite qu'un nœud ajouté demain fasse passer l'un pour l'autre.
  const cueillir46 = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir46(c, pred, acc)); return acc; };
  const avisDe = (ns) => ns.filter((n) => n.classList && n.classList.contains("rf-hint") && !n.classList.contains("bad"));
  const refusDe = (ns) => ns.filter((n) => n.classList && n.classList.contains("rf-hint") && n.classList.contains("bad"));
  const dernier = (ns) => ns[ns.length - 1];

  const rendre = (viz, prefs, mode, reglage, id = PANNEAU, cle = CLE_PANNEAU) => {
    prefs.prefSet("viz_axes", reglage ? { [cle]: reglage } : {});
    return viz.noeudsDeVizReglee(mode, COLS, ROWS, "", "", id, () => {});
  };

  // (a) INSTRUMENT + CONTRÔLE POSITIF.
  const nsNu = rendre(vizFR, prefsFR, "bar", null);
  const empreinteNue = dernier(nsNu).outerHTML;
  exiger(avisDe(nsNu).length === 0, `(46a) sans aucun réglage, la vue prononce déjà un aveu de réglage privé : « ${avisDe(nsNu).map((n) => n.textContent).join(" ")} »`);
  exiger(empreinteNue === vizFR.vizElement("bar", COLS, ROWS, "", "").outerHTML,
    "(46a) instrument : sans réglage, la fabrique réglée ne rend PLUS l'appel `vizElement` d'origine — l'empreinte de référence ne vaut rien");
  exiger(empreinteNue.length > 40, "(46a) instrument : l'empreinte du graphe est quasi vide, une comparaison d'empreintes ne distinguerait rien");

  const nsEcarte = rendre(vizFR, prefsFR, "bar", { x: "count" });
  const avisEcarte = avisDe(nsEcarte);
  exiger(avisEcarte.length === 1, `(46a) un réglage qui DÉPLACE une colonne ne fait apparaître aucun aveu (${avisEcarte.length} trouvé(s)) : le lecteur croit voir le panneau tel qu'il est enregistré`);
  exiger(dernier(nsEcarte).outerHTML !== empreinteNue,
    "(46a) instrument : le réglage ne change PAS ce qui est rendu — l'aveu porterait sur une divergence qui n'existe pas, et ce témoin ne prouverait rien");
  const texteEcarte = avisEcarte.map((n) => n.textContent).join(" ");
  exiger(/VOTRE compte/.test(texteEcarte) && /pas dans le panneau/.test(texteEcarte),
    `(46a) l'aveu ne dit pas que le réglage vit sur le compte du lecteur et non dans le panneau : « ${texteEcarte} »`);
  exiger(/personne d’autre ne les voit/.test(texteEcarte), `(46a) l'aveu ne dit pas que personne d'autre ne voit ces axes : « ${texteEcarte} »`);
  exiger(/\(par défaut\)/.test(texteEcarte), `(46a) l'aveu n'indique pas le chemin du retour vers ce que voient les autres : « ${texteEcarte} »`);

  // (b) LA MUTATION QUI PROUVE LA DÉRIVATION : un réglage SANS divergence ne dit rien, et rend pareil.
  const nsMeme = rendre(vizFR, prefsFR, "bar", { x: "host", y: "count" });
  exiger(avisDe(nsMeme).length === 0,
    `(46b) un réglage qui REDONNE l'ordre par défaut fait tout de même parler la vue (« ${avisDe(nsMeme).map((n) => n.textContent).join(" ")} ») : l'aveu suit l'EXISTENCE d'un réglage, pas la DIVERGENCE — il crierait au loup`);
  exiger(dernier(nsMeme).outerHTML === empreinteNue,
    "(46b) instrument : un réglage qui redonne l'ordre par défaut ne rend PAS la même chose que l'absence de réglage — le silence de (46b) ne prouverait alors rien");

  // (c) L'ORDRE NOMMÉ VIENT DE LA REPRÉSENTATION, pas d'une phrase écrite.
  const nsHeat = rendre(vizFR, prefsFR, "heatmap", { x: "count" });
  const texteHeat = avisDe(nsHeat).map((n) => n.textContent).join(" ");
  exiger(vizFR.sondage("bar").fentes[1] === false && vizFR.sondage("heatmap").fentes[1] === true,
    "(46c) instrument : `bar` et `heatmap` ne se distinguent plus par la fente du milieu — les deux ordres attendus ci-dessous ne seraient plus différents");
  exiger(/«\s*host → count\s*»/.test(texteEcarte), `(46c) sur \`bar\`, l'aveu ne nomme pas l'ordre « host → count » que le panneau enregistré remet au graphe : « ${texteEcarte} »`);
  exiger(/«\s*host → source → count\s*»/.test(texteHeat), `(46c) sur \`heatmap\`, l'aveu ne nomme pas l'ordre « host → source → count » : la phrase ne suit pas ce que la représentation LIT : « ${texteHeat} »`);

  // (d) UN CHOIX IMPOSSIBLE : refus ET aveu.
  const nsRefus = rendre(vizFR, prefsFR, "bar", { x: "colonne_absente" });
  exiger(refusDe(nsRefus).length === 1 && /Graphe refusé/.test(refusDe(nsRefus)[0].textContent),
    `(46d) instrument : un réglage nommant une colonne absente ne produit plus de refus — le cas exercé n'est pas celui décrit`);
  exiger(avisDe(nsRefus).length === 1,
    "(46d) le lecteur voit un REFUS là où les autres voient un graphe, et rien ne lui dit que ce refus tient à SON réglage");

  // (e) SANS IDENTITÉ DE PANNEAU : rien à déclarer, et le témoin épingle que ce silence ne déborde pas.
  const nsSansPanneau = rendre(vizFR, prefsFR, "bar", { x: "count" }, 0, CLE_SANS_PANNEAU);
  exiger(dernier(nsSansPanneau).outerHTML !== empreinteNue,
    "(46e) instrument : sans identité de panneau le réglage n'est même plus APPLIQUÉ — le silence mesuré ci-dessous serait celui d'un réglage inerte");
  exiger(avisDe(nsSansPanneau).length === 0,
    `(46e) un appelant SANS identité de panneau s'entend parler d'un panneau enregistré qui n'existe pas : « ${avisDe(nsSansPanneau).map((n) => n.textContent).join(" ")} »`);

  // (f) LES DEUX LANGUES.
  localStorage.setItem("soc_lang", "en");
  const vizEN = await import(url41("viz.js", SUF41));
  const prefsEN = await import(url41("prefs.js", SUF41));
  localStorage.removeItem("soc_lang");
  const nsEN = rendre(vizEN, prefsEN, "bar", { x: "count" });
  const texteEN = avisDe(nsEN).map((n) => n.textContent).join(" ");
  exiger(avisDe(nsEN).length === 1 && /YOUR account/.test(texteEN) && /nobody else sees them/.test(texteEN) && /“\(default\)”/.test(texteEN),
    `(46f) sous LANG='en' l'aveu n'est pas rendu en anglais : « ${texteEN} »`);
  exiger(!/Réglage privé/.test(texteEN), `(46f) sous LANG='en' l'aveu rend encore la phrase française : « ${texteEN} »`);
  exiger(/«\s*host → count\s*»/.test(texteEN) === false && /“host → count”/.test(texteEN),
    `(46f) sous LANG='en' l'ordre nommé garde les guillemets français : « ${texteEN} »`);

  // (h) LE CHEMIN DE RETOUR QUE L'AVEU NOMME EXISTE VRAIMENT, Y COMPRIS QUAND TOUT S'EST DÉROBÉ.
  //     Un réglage posé sur trois colonnes SURVIT à une requête réécrite qui n'en rend plus qu'une : il
  //     continuait de s'appliquer pendant que la barre — seul contrôle capable de le défaire — ne
  //     s'affichait plus (elle était conditionnée à DEUX colonnes), et le sélecteur, lui, aurait affiché
  //     « (par défaut) » alors que le réglage était actif. Trois façons de nommer une sortie qui n'existe
  //     pas. Le témoin la PREND.
  const UNE_COL = ["count"], UNE_ROW = [[12], [7]];
  prefsFR.prefSet("viz_axes", { [CLE_PANNEAU]: { x: "host" } });
  const nsAmputee = vizFR.noeudsDeVizReglee("bar", UNE_COL, UNE_ROW, "", "", PANNEAU, () => {});
  const selects = (ns) => ns.flatMap((n) => cueillir46(n, (e) => e.tagName === "SELECT", []));
  const selAmputee = selects(nsAmputee);
  exiger(refusDe(nsAmputee).length === 1, "(46h) instrument : le réglage devenu impossible ne produit plus de refus — le cas exercé n'est pas celui décrit");
  exiger(avisDe(nsAmputee).length === 1, "(46h) le réglage privé ne se dit plus quand la colonne choisie a disparu du résultat — le lecteur voit un texte que les autres ne voient pas, sans savoir qu'il tient à SON réglage");
  exiger(selAmputee.length > 0, "(46h) plus aucun sélecteur n'est rendu alors qu'un réglage s'applique : l'aveu nomme « (par défaut) » comme sortie, et cette sortie n'est pas là");
  // Les options d'un `select` CONSTRUIT (et non posé en balisage) vivent dans ses enfants : le shim ne
  // remplit `.options` qu'à l'analyse d'une chaîne de balisage. Lire les enfants, c'est lire l'arbre réel.
  const optionsDe = (sel) => (sel.children || []).filter((c) => c.tagName === "OPTION");
  const selX = selAmputee.find((e) => optionsDe(e).some((o) => o.value === "host"));
  exiger(!!selX, `(46h) la colonne CHOISIE « host », absente du résultat, n'est offerte par aucun sélecteur : re-choisir « (par défaut) » ne serait pas un changement, et le réglage n'aurait pas de sortie`);
  exiger(!!selX && selX.value === "host", `(46h) le sélecteur affiche « ${selX && selX.value} » alors que le réglage appliqué est « host » : le contrôle dit le contraire de ce qui s'applique`);
  if (selX) { selX.value = ""; selX.onchange(); }
  exiger(vizFR.reglageLu(CLE_PANNEAU) === null,
    `(46h) revenir à « (par défaut) » n'a PAS défait le réglage (${JSON.stringify(vizFR.reglageLu(CLE_PANNEAU))}) : la sortie que l'aveu nomme ne sort de rien`);
  const nsRevenue = vizFR.noeudsDeVizReglee("bar", UNE_COL, UNE_ROW, "", "", PANNEAU, () => {});
  exiger(refusDe(nsRevenue).length === 0 && avisDe(nsRevenue).length === 0,
    "(46h) après le retour à « (par défaut) » la vue refuse ou avoue encore : le geste n'a pas rendu le panneau tel qu'il est enregistré");

  // (i) UNE REPRÉSENTATION QUI NE LIT PAS UNE FENTE NE FAIT PAS DISPARAÎTRE LE RÉGLAGE POSÉ DESSUS —
  //     elle le laisse s'appliquer. La fente doit donc rester OFFERTE pour être défaite ; et comme la
  //     représentation ne la LIT pas, rien ne diverge et l'aveu se tait. Les deux moitiés comptent :
  //     l'aveu qui parlerait ici crierait au loup, et la fente qu'on n'offrirait pas serait un piège.
  exiger(vizFR.sondage("stat").trace === false && vizFR.sondage("stat").fentes[0] === false,
    "(46i) instrument : `stat` trace ou lit sa première fente — la représentation choisie ne démontre plus rien");
  const nsStat = rendre(vizFR, prefsFR, "stat", { x: "count" });
  exiger(avisDe(nsStat).length === 0,
    `(46i) sur une représentation qui NE LIT PAS l'abscisse, régler l'abscisse fait tout de même parler la vue (« ${avisDe(nsStat).map((n) => n.textContent).join(" ")} ») : l'aveu suit l'ordre BRUT et non ce que la représentation lit`);
  const selStatX = selects(nsStat).find((e) => e.value === "count");
  exiger(!!selStatX, "(46i) la fente réglée n'est plus offerte sur une représentation qui ne la lit pas : le réglage s'applique quand même et ne peut plus être défait");

  // (g) LA PHRASE SUR L'INSTANTANÉ EST DÉRIVÉE DU SOURCE, jamais crue sur parole.
  const srcDash = readFileSync(path.join(WEB, "dashboards.js"), "utf8");
  const corpsCapture = srcDash.match(/async function captureSnapshot\([\s\S]*?\n\}/);
  exiger(!!corpsCapture, "(46g) instrument : `captureSnapshot` introuvable dans `dashboards.js` — la phrase « l'instantané ne les emporte pas » n'est plus adossée à rien");
  if (corpsCapture) {
    exiger(/vizElement\(/.test(corpsCapture[0]),
      "(46g) instrument : l'aperçu de l'instantané ne rend plus par `vizElement` — le chemin que la phrase décrit n'est plus celui-là");
    exiger(!/noeudsDeVizReglee/.test(corpsCapture[0]),
      "(46g) l'aperçu de l'instantané passe désormais par la fabrique RÉGLÉE : la phrase « l'instantané partageable ne les emporte pas » est devenue FAUSSE, et elle est servie telle quelle au lecteur");
  }

  prefsFR.prefSet("viz_axes", undefined);
  prefsEN.prefSet("viz_axes", undefined);
  try { localStorage.removeItem("plume_prefs"); } catch (e) {}

  console.log("[axes-partages] le réglage d'axes d'un panneau vit sur le COMPTE du lecteur, et la vue le DIT dès que ce qu'elle montre s'écarte de ce que le panneau enregistré sert : l'aveu nomme l'ordre que les autres voient (dérivé de la représentation — deux colonnes sur `bar`, trois sur `heatmap`), nomme le chemin du retour, et accompagne aussi le refus. Un réglage qui REDONNE l'ordre par défaut ne dit rien et rend une empreinte byte-identique à l'absence de réglage ; un appelant sans identité de panneau ne dit rien non plus. Les deux langues sont rendues. La phrase sur l'instantané partageable est adossée au source : `captureSnapshot` rend par `vizElement`, le chemin sans réglage.");
}

// ---------------------------------------------------------------------------------------------
// 43. UN GESTE QUI EXISTE ET QU'ON NE TROUVE PAS EST, POUR CELUI QUI L'A CHERCHÉ, UN GESTE ABSENT
//     (`P11.14-d`) — ET UN REFUS QUI DÉCLARE UN FONDEMENT QU'IL IGNORE FABRIQUE (`P11.14-h`).
//     (a) LE MÉCANISME EXISTE, ET CE TÉMOIN EST VERT AVANT COMME APRÈS : un cas terminé rendu à un
//         éditeur porte DÉJÀ son bouton « Rouvrir ». C'est lui qui interdit de raconter que la console
//         n'avait pas de réouverture — le constat d'origine est réfuté sur le mécanisme.
//     (b) LA PISTE DU RAFRAÎCHISSEMENT EST RÉFUTÉE PAR MUTATION, pas par lecture. Un cas EN COURS est
//         résolu depuis son propre bouton, à travers la fenêtre de confirmation partagée ; la VALEUR qui
//         change est le jeu des libellés de la barre d'actions du détail — « Résoudre » s'en va,
//         « Rouvrir » y entre — sans qu'aucun rechargement de page n'ait lieu. Le témoin relève la barre
//         AVANT pour que la comparaison porte sur un changement et non sur un état.
//     (c) CE QUI MANQUAIT VRAIMENT : hors du détail, rien ne nommait le geste. Le cadre d'état d'une
//         LIGNE de la liste le nomme désormais et dit OÙ il attend. Témoin inverse obligatoire : la ligne
//         d'un cas EN COURS ne nomme ni le geste ni sa place — une version qui l'écrirait toujours
//         passerait le premier témoin et mentirait sur la moitié des lignes.
//     (d) LE RÔLE CHANGE LA PHRASE, PAS SEULEMENT LA PRÉSENCE DU BOUTON. Le même cas terminé, lu par un
//         rôle sans écriture, dit que « Rouvrir » demande un rôle et que ce geste n'est proposé nulle
//         part — au lieu de promettre une sortie que ce lecteur ne verra jamais. Les deux phrases sont
//         DIFFÉRENTES, et celle de l'éditeur ne parle pas de rôle.
//     (e) LES DEUX SURFACES DU DÉTAIL S'ACCORDENT parce qu'elles ont un seul auteur : le cadre d'état et
//         la raison portée par le sélecteur inerte nomment le MÊME geste et la MÊME place ; sur un cas en
//         cours, aucune des deux ne les nomme.
//     (f) `P11.14-h` — LE REFUS DE PIVOTER NE FABRIQUE PLUS. Sa phrase affirmait deux choses qu'aucune
//         valeur servie ne porte : que l'alerte « n'a ni règle » (faux dès que la règle a été SUPPRIMÉE —
//         le lien tombe avec la JOINTURE, pas avec la recherche) et que « sa justification est l'état
//         qu'elle porte » (une FONDATION déclarée sans qu'aucun champ ne la déclare). Le témoin exige
//         désormais la phrase DÉRIVÉE — aucune fenêtre servie — l'aveu de la seconde impasse, et
//         l'absence des deux fabrications. Témoin positif : une alerte qui PORTE son lien reçoit un autre
//         mot et reste cliquable.
//     CE QUE CE TÉMOIN NE TIENT PAS : que la personne aurait trouvé le geste — il tient ce que chaque
//     surface DIT, jamais ce qu'un lecteur en fait ; rien de la mise en page ni du style calculé (un
//     survol reste un attribut du document ici) ; et, pour `P11.14-h`, il ne tient PAS le fondement
//     lui-même — personne ne le déclare encore, et c'est exactement ce que la clé garde ouvert.
// ---------------------------------------------------------------------------------------------
{
  const { caseRow, renderCaseDetail } = await import(pathToFileURL(path.join(WEB, "cases.js")).href);
  const { pivotDUneAlerte, dessinerLaListePlate, alertListModel } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const cueillir = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir(c, pred, acc)); return acc; };
  const rep = (o) => ({ ok: true, status: 200, text: async () => JSON.stringify(o) });
  const qsOrigine = document.querySelector, fetchOrigine = globalThis.fetch;
  const etatOrigine = { auth: S.AUTH, sel: S.caseSelectedId, g: S.alertGroupBy, a: S.alertGroupAll, u: S.alertUncased };

  const encours = { id: 7, title: "Balayage", status: "in_progress", severity: 3, priority: 2, items: 0, ts: 1000, updated: 1000 };
  const clos = { id: 9, title: "Ancien", status: "closed", severity: 1, priority: 4, items: 0, ts: 900, updated: 950, closed_ts: 960 };
  let statutServi = "in_progress";
  const detail = new Element("div"); detail.id = "case-detail";
  document.querySelector = (sel) => (sel === "#case-detail" ? detail : sel === "#cases-list" ? null : new Element("div"));
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (/\/cases\/\d+\/links$/.test(u)) return rep({ links: [] });
    if (/\/cases\/\d+\/runbooks$/.test(u)) return rep({ incident_tier: null, available: [] });
    if (/\/cases\/\d+\/steps$/.test(u)) return rep({ steps: [], progress: { total: 0, done: 0, skipped: 0 }, runbook: null });
    if (/\/cases\/7$/.test(u) && init && init.method === "POST") { statutServi = JSON.parse(init.body).status; return rep({}); }
    if (/\/cases\/9$/.test(u)) return rep(clos);
    if (/\/cases\/7$/.test(u)) return rep({ ...encours, status: statutServi });
    return rep({ cases: [], total: 0 });
  };
  const libelles = (hote) => cueillir(hote, (e) => e.tagName === "BUTTON", []).map((b) => b.textContent);
  const cadre = (c) => cueillir(caseRow(c), (e) => e.classList.contains("casest"), [])[0];
  try {
    S.AUTH = { user: "eve", role: "editor" };

    // (a) LE GESTE EXISTE — vert avant comme après le correctif.
    const hClos = new Element("div"); renderCaseDetail(hClos, clos); await tick();
    exiger(libelles(hClos).includes("Rouvrir"), `(43a) un cas terminé rendu à un éditeur ne porte AUCUN bouton « Rouvrir » : le constat ne serait plus « introuvable » mais « absent » — ${JSON.stringify(libelles(hClos))}`);

    // (b) LA BARRE SE RECOMPOSE SANS RECHARGEMENT — preuve par MUTATION, état relevé AVANT.
    S.caseSelectedId = 7; statutServi = "in_progress";
    renderCaseDetail(detail, encours); await tick();
    const avant = libelles(detail);
    exiger(avant.includes("Résoudre") && !avant.includes("Rouvrir"), `(43b) instrument : la barre d'un cas EN COURS ne part pas de « Résoudre » sans « Rouvrir » — ${JSON.stringify(avant)}`);
    const resoudre = cueillir(detail, (e) => e.tagName === "BUTTON" && e.textContent === "Résoudre", [])[0];
    const geste = resoudre.onclick(); await tick();
    const ov = document.body.children.filter((c) => c.classList && c.classList.contains("modal-ov")).pop();
    exiger(!!ov, "(43b) instrument : le bouton « Résoudre » n'a posé aucune fenêtre de confirmation, la suite ne prouverait rien");
    ov.children[0].children[0].onsubmit({ preventDefault() {} });
    await geste; await tick();
    const apres = libelles(detail);
    exiger(statutServi === "resolved", `(43b) instrument : la route n'a pas reçu la résolution (statut servi « ${statutServi} »)`);
    exiger(apres.includes("Rouvrir") && !apres.includes("Résoudre"), `(43b) après la résolution, la barre du détail ne s'est PAS recomposée sans rechargement : ${JSON.stringify(avant)} -> ${JSON.stringify(apres)} — c'est la piste que \`P11.14-d\` proposait, et elle est réfutée`);

    // (c) LA LIGNE DE LA LISTE NOMME LE GESTE ET SA PLACE. Témoin inverse : un cas en cours ne les nomme pas.
    const tClos = (cadre(clos) || {}).title || "", tEnCours = (cadre(encours) || {}).title || "";
    exiger(/Rouvrir/.test(tClos) && /barre d'actions/.test(tClos), `(43c) hors du détail, rien ne nomme le geste de réouverture ni l'endroit où il attend : « ${tClos} »`);
    exiger(!/Rouvrir/.test(tEnCours) && !/barre d'actions/.test(tEnCours), `(43c) témoin inverse : la ligne d'un cas EN COURS annonce une réouverture — une version qui l'écrit toujours passerait le témoin précédent : « ${tEnCours} »`);

    // (d) LE RÔLE CHANGE LA PHRASE.
    S.AUTH = { user: "bob", role: "viewer" };
    const tLecteur = (cadre(clos) || {}).title || "";
    exiger(tLecteur !== tClos, "(43d) le cadre d'état dit la même chose à qui peut écrire et à qui ne peut pas : le lecteur lit une promesse de geste qu'il ne verra jamais");
    exiger(/Rouvrir/.test(tLecteur) && /rôle/.test(tLecteur) && /nulle part/.test(tLecteur), `(43d) le lecteur n'apprend ni le nom du geste ni pourquoi il ne le voit nulle part : « ${tLecteur} »`);
    exiger(!/rôle/.test(tClos), `(43d) témoin inverse : la phrase de l'éditeur parle de rôle — les deux causes redeviennent indiscernables : « ${tClos} »`);
    S.AUTH = { user: "eve", role: "editor" };

    // (e) LES DEUX SURFACES DU DÉTAIL S'ACCORDENT (un seul auteur).
    const raison = (c) => { const h = new Element("div"); renderCaseDetail(h, c); return (cueillir(h, (e) => e.tagName === "LABEL" && /^Statut/.test(e.textContent), [])[0] || {}).textContent || ""; };
    const rClos = raison(clos), rEnCours = raison(encours);
    exiger(/Rouvrir/.test(rClos) && /barre d'actions/.test(rClos), `(43e) la raison du sélecteur inerte ne nomme pas le même geste ni la même place que le cadre d'état : « ${rClos} »`);
    exiger(!/Rouvrir/.test(rEnCours) && !/barre d'actions/.test(rEnCours), `(43e) témoin inverse : un cas EN COURS porte la sortie d'un état terminal : « ${rEnCours} »`);
  } finally {
    document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine;
    S.AUTH = etatOrigine.auth; S.caseSelectedId = etatOrigine.sel;
  }

  // (f) `P11.14-h` — LE REFUS NE FABRIQUE PLUS NI RÈGLE ABSENTE NI FONDEMENT.
  const listeA = new Element("div");
  document.querySelector = (sel) => (sel === "#alerts .body" ? listeA : new Element("div"));
  globalThis.fetch = async () => rep({ alerts: [], total: 0 });
  const regleSupprimee = { id: 11, ts: 1000, rule: "rule.42", severity: 3, title: "Compte verrouille", status: "new", detail: "search action=lock", mitre: "", sources: "", case_id: null, acked_at: 0, acked_by: "", search_link: null };
  const avecLien = { id: 12, ts: 1000, rule: "rule.3", severity: 2, title: "Scan de ports", status: "new", detail: "search source=ufw | stats count", mitre: "", sources: "ufw", case_id: null, acked_at: 0, acked_by: "", window_s: 600, search_link: { query: "search source=ufw | stats count", from: 400, to: 1000 } };
  try {
    S.AUTH = { user: "eve", role: "editor" };
    const refus = pivotDUneAlerte(regleSupprimee), exact = pivotDUneAlerte(avecLien);
    exiger(exact.mode === "exact", `(43f) instrument : une alerte qui PORTE son lien n'est pas lue comme un pivot exact (« ${exact.mode} ») — le témoin de refus ne prouverait rien`);
    exiger(refus.mode === "aucun", `(43f) instrument : l'alerte sans fenêtre servie n'atteint pas la troisième branche (« ${refus.mode} »)`);
    exiger(refus.survol !== exact.survol, "(43f) le refus et le pivot exact rendent le même mot");
    exiger(!/n'a ni règle/.test(refus.survol), `(43f) le refus affirme encore que l'alerte n'a AUCUNE règle : c'est faux dès que la règle a été supprimée — le lien tombe avec la jointure, pas avec la recherche : « ${refus.survol} »`);
    exiger(!/justification est l'état/.test(refus.survol), `(43f) le refus DÉCLARE encore sur quoi l'alerte est fondée, alors qu'aucun champ servi ne le déclare — la fabrication d'un étage plus haut (\`P11.14-h\`) : « ${refus.survol} »`);
    exiger(/fenêtre d'évaluation/.test(refus.survol) && /refuse/.test(refus.survol), `(43f) le refus ne dit plus ce qui est DÉRIVÉ (aucune fenêtre servie) ni qu'il refuse : « ${refus.survol} »`);
    exiger(/FONDE/.test(refus.survol) && /ne le déclare/.test(refus.survol), `(43f) le refus ne dit pas la seconde impasse — que rien de servi ne déclare le fondement de l'alerte : « ${refus.survol} »`);
    S.alertGroupBy = ""; S.alertGroupAll = false; S.alertUncased = true;
    dessinerLaListePlate(listeA, alertListModel(), [regleSupprimee, avecLien], undefined);
    const rendu = String(listeA.innerHTML);
    exiger(/data-pivot="aucun"[^>]*aria-disabled="true"/.test(rendu), "(43f) la ligne du refus ne porte plus son inertie aux aides techniques : le refus redeviendrait un clic sans effet");
    exiger(!/data-pivot="exact"[^>]*aria-disabled/.test(rendu), "(43f) témoin inverse : la ligne d'un pivot EXACT est rendue inerte elle aussi");
    exiger(rendu.includes(refus.survol), "(43f) le survol de la ligne refusée n'est pas le mot du refus : le survol et le clic ont deux auteurs, et ils divergeront");
  } finally {
    document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine;
    S.AUTH = etatOrigine.auth; S.alertGroupBy = etatOrigine.g; S.alertGroupAll = etatOrigine.a; S.alertUncased = etatOrigine.u;
  }
  console.log(`[sortie-et-fondement] le geste de réouverture EXISTAIT (le constat est réfuté sur le mécanisme) et la barre du détail se RECOMPOSE sans rechargement — « Résoudre » sort, « Rouvrir » entre, par le bouton et la confirmation partagée. Ce qui manquait est dit : hors du détail, la ligne d'un cas terminé NOMME le geste et l'endroit où il attend, un cas en cours ne le fait pas, et un lecteur sans écriture apprend que « Rouvrir » demande un rôle et n'est proposé nulle part au lieu de lire une promesse. Le refus de pivoter d'une alerte, lui, cesse de fabriquer : il n'affirme plus qu'elle « n'a ni règle » (faux pour une règle supprimée) ni ce sur quoi elle est fondée — il dit la fenêtre absente, refuse, et AVOUE que rien de servi ne déclare ce fondement. Ce que ce témoin NE tient PAS : que la personne aurait trouvé le geste ; rien de la mise en page ni du style calculé ; et pas le fondement lui-même, que personne ne déclare encore.`);
}

// ---------------------------------------------------------------------------------------------
// 45. UNE REPRÉSENTATION QUI NE PEUT PAS EXPRIMER CETTE DONNÉE N'EST PAS OFFERTE POUR ELLE
//     (`P11.18-p`). Le défaut visé n'est pas un graphe laid : c'est un graphe FAUX, et un graphe faux
//     se lit comme un graphe. MESURÉ ICI, sur les représentations RÉELLES et sans aucun réglage :
//     six d'entre elles ramenaient une ordonnée textuelle à ZÉRO et rendaient quand même une figure —
//     des barres à `width: 0%` avec le mot imprimé à côté, une courbe dont tous les points se
//     superposent, une jauge « 0 / 1 » dont les DEUX termes sont fabriqués, un camembert qui annonce
//     « aucune donnée » pendant que trois lignes existent, et une grille de chaleur entièrement vide.
//     La septième traçante, `histogram`, n'avouait que si AUCUNE valeur n'était un nombre : sur une
//     colonne MÉLANGÉE elle rendait la valeur textuelle en barre de hauteur zéro, comme les autres.
//
//     CE QUE CE TÉMOIN TIENT, ET DANS LES DEUX SENS. Le NÉGATIF est le dispatcher SANS la porte
//     (`vizSansPorte`, que seul le sondage a le droit d'appeler) : il rend TOUJOURS les six figures
//     fausses, chacune reconnue à la signature exacte relevée sur banc — sans quoi ce témoin
//     prouverait seulement que quelque chose a changé, pas que le défaut existait. Le POSITIF est la
//     porte : sur la même donnée, chaque représentation qui coerce est REFUSÉE, et le refus NOMME la
//     colonne, le compte et un exemple. Et la NON-RÉGRESSION est byte-identique : sur une ordonnée
//     numérique, la porte et le dispatcher nu rendent le MÊME balisage, pour les neuf modes.
//
//     RIEN N'EST ÉNUMÉRÉ ICI. Les modes sont LUS dans le dispatcher, et le partage entre « coerce »
//     et « ne coerce pas » vient du SONDAGE de `P11.18-a`, c'est-à-dire de la représentation
//     elle-même. Un mode posé demain entre dans ce témoin sans qu'on l'écrive.
//
//     CE QUE CE TÉMOIN NE TIENT PAS : la mise en page et le style calculé (section 0) — une barre à
//     `width: 0%` est lue ici sur l'attribut de style EN LIGNE, jamais sur l'encre peinte ; et il ne
//     dit rien des panneaux SEMÉS par le démon, dont les requêtes vivent hors de `web/`.
// ---------------------------------------------------------------------------------------------
{
  const viz = await import(pathToFileURL(path.join(WEB, "viz.js")).href);
  const source = readFileSync(path.join(WEB, "viz.js"), "utf8");

  // -- LES MODES SONT LUS DANS LE DISPATCHER, PAS RECOPIÉS ------------------------------------
  const iDeb = source.indexOf("function vizSansPorte(");
  const iFin = source.indexOf("function vizElement(");
  exiger(iDeb >= 0 && iFin > iDeb, "(45-instrument) le dispatcher de représentations n'est plus lisible dans web/viz.js : les modes de ce témoin ne dériveraient de rien");
  const corpsDispatcher = source.slice(iDeb, iFin > iDeb ? iFin : iDeb + 1);
  const MODES = [...new Set([...corpsDispatcher.matchAll(/mode === '([a-z]+)'/g)].map((m) => m[1]))].concat("table");
  exiger(MODES.length >= 9, `(45-instrument) ${MODES.length} mode(s) lus dans le dispatcher, plancher 9 : la lecture est cassée et ce qui suit ne couvrirait presque rien`);

  // -- LE PARTAGE VIENT DE LA REPRÉSENTATION, PAS D'UNE TABLE ÉCRITE ICI ----------------------
  const coercantes = MODES.filter((m) => viz.sondage(m).ordonneeNumerique);
  const libres = MODES.filter((m) => !viz.sondage(m).ordonneeNumerique);
  exiger(coercantes.length > 0 && libres.length > 0,
    `(45a-instrument) le sondage ne partage plus les modes (${coercantes.length} coercent, ${libres.length} non) : un verdict constant ne mesurerait rien`);

  const COLS = ["host", "sev"];
  const TXT = [["a", "rouge"], ["b", "vert"], ["c", "rouge"]];
  const MIXTE = [["a", 3], ["b", "n/a"], ["c", 1]];
  // Le jeu de NON-RÉGRESSION doit avoir ses DEUX fentes valides — la porte lit l'abscisse aussi.
  const COLS_OK = ["bucket", "n"];
  const NUM = [[10, 3], [20, 9], [30, 1]];
  const trouver = (n, pred, out = []) => { if (n && pred(n)) out.push(n); for (const c of (n && n.children) || []) trouver(c, pred, out); return out; };
  const classe = (n, c) => trouver(n, (x) => x.classList && x.classList.contains(c));

  // ---- (a) LE NÉGATIF : SANS LA PORTE, LES SIX FIGURES FAUSSES SONT TOUJOURS LÀ ----
  // Chacune à sa signature MESURÉE, jamais à une phrase — une phrase se reformule.
  const nu = (m, rows) => viz.vizSansPorte(m, COLS, rows, "", "");
  const barres = classe(nu("bar", TXT), "barfill").map((n) => n.style.width);
  exiger(barres.length === 3 && barres.every((w) => w === "0%"),
    `(45a-négatif) « bar » sans la porte ne trace plus ses trois barres à 0 % de large (${JSON.stringify(barres)}) : la signature du défaut a bougé, et le positif ne prouverait plus rien`);
  exiger(nu("bar", TXT).textContent.includes("rouge"),
    "(45a-négatif) « bar » sans la porte n'imprime plus le texte à côté de la barre vide — c'est CE voisinage qui rend le graphe faux crédible");
  const pts = (trouver(nu("line", TXT), (n) => n.tagName === "POLYLINE")[0] || { attributes: {} }).attributes.points || "";
  const distincts = new Set(pts.split(" ").filter(Boolean));
  exiger(pts && distincts.size === 1,
    `(45a-négatif) « line » sans la porte n'écrase plus ses abscisses sur un point unique (${distincts.size} point(s) distincts sur « ${pts} »)`);
  exiger(/0\s*\/\s*1/.test(nu("gauge", TXT).textContent.replace(/\s+/g, " ")),
    `(45a-négatif) « gauge » sans la porte n'affiche plus le rapport fabriqué « 0 / 1 » : « ${nu("gauge", TXT).textContent} »`);
  for (const m of ["pie", "donut"]) exiger(/aucune donnée|no data/i.test(nu(m, TXT).textContent) && TXT.length === 3,
    `(45a-négatif) « ${m} » sans la porte n'annonce plus une ABSENCE alors que ${TXT.length} lignes existent : « ${nu(m, TXT).textContent} »`);
  const cellules = classe(nu("heatmap", TXT), "heatcell").map((n) => n.textContent);
  exiger(cellules.length > 0 && cellules.every((t) => t === ""),
    `(45a-négatif) « heatmap » sans la porte ne rend plus une grille ENTIÈREMENT vide sur des valeurs qui existent (${JSON.stringify(cellules)})`);
  // `histogram` : son aveu ne sortait QUE si aucune valeur n'était un nombre. Sur une colonne MÉLANGÉE
  // il rendait la valeur textuelle en barre de hauteur ZÉRO — donc son honnêteté n'était que partielle.
  const hauteurs = trouver(viz.vizSansPorte("histogram", COLS, MIXTE, "", ""), (n) => n.tagName === "RECT").map((n) => Number(n.attributes.height));
  exiger(hauteurs.length === 3 && hauteurs.filter((h) => h === 0).length === 1,
    `(45a-négatif) « histogram » sans la porte ne rend plus la valeur non numérique d'une colonne MÉLANGÉE en barre de hauteur zéro (${JSON.stringify(hauteurs)}) : l'aveu qu'il rend sur du tout-texte cachait ce cas`);
  // Aucune de ces figures ne DISAIT quoi que ce soit du problème : ni la colonne, ni le mot.
  for (const m of coercantes) {
    const t = nu(m, TXT).textContent;
    exiger(!t.includes("sev") && !/FAUX|FALSE/.test(t),
      `(45a-négatif) « ${m} » sans la porte nomme déjà la colonne ou dit déjà le faux (« ${t.slice(0, 100)} ») : le positif ne mesurerait plus rien`);
  }

  // ---- (b) LE POSITIF : LA PORTE REFUSE, ET LE REFUS DIT POURQUOI ----
  for (const m of coercantes) {
    const t = viz.vizElement(m, COLS, TXT, "", "").textContent;
    exiger(/Graphe refusé|Chart refused/.test(t), `(45b) « ${m} » sur une ordonnée textuelle rend encore une figure au lieu d'un refus : « ${t.slice(0, 120)} »`);
    exiger(t.includes("sev") && t.includes("3") && t.includes("rouge"),
      `(45b) le refus de « ${m} » ne nomme pas la colonne, le compte et un exemple : « ${t.slice(0, 200)} »`);
  }
  for (const m of libres) {
    const t = viz.vizElement(m, COLS, TXT, "", "").textContent;
    exiger(!/Graphe refusé|Chart refused/.test(t) && t.includes("rouge"),
      `(45b) « ${m} » n'exprime PAS son ordonnée en nombre (sondage) et se voit pourtant refusée, ou perd la donnée : « ${t.slice(0, 120)} »`);
  }
  // La colonne MÉLANGÉE, qui est le cas dangereux : la valeur fausse y serait noyée dans des vraies.
  for (const m of coercantes) {
    const t = viz.vizElement(m, COLS, MIXTE, "", "").textContent;
    exiger(/Graphe refusé|Chart refused/.test(t) && t.includes("n/a"),
      `(45b) « ${m} » trace encore une colonne MÉLANGÉE, où une seule valeur sur trois n'est pas un nombre : « ${t.slice(0, 140)} »`);
  }
  // UNE COLONNE SANS AUCUNE VALEUR N'EST PAS UNE COLONNE À ZÉRO — et la phrase le dit autrement.
  const vide = viz.vizElement("bar", COLS, [["a", null], ["b", ""], ["c", null]], "", "").textContent;
  exiger(/AUCUNE valeur|NO value/.test(vide) && !/n’en sont pas|are not numbers/.test(vide),
    `(45b) une ordonnée sans aucune valeur reçoit la phrase des valeurs non numériques, qui compterait « 0 sur 0 » : « ${vide.slice(0, 160)} »`);

  // ---- (c) LA NON-RÉGRESSION EST BYTE-IDENTIQUE SUR UNE ORDONNÉE NUMÉRIQUE ----
  let identiques = 0, changes = 0;
  for (const m of MODES) {
    if (viz.vizSansPorte(m, COLS_OK, NUM, "q", "").outerHTML === viz.vizElement(m, COLS_OK, NUM, "q", "").outerHTML) identiques++; else changes++;
  }
  exiger(changes === 0, `(45c) ${changes} mode(s) sur ${MODES.length} ne rendent plus le MÊME balisage qu'avant la porte sur un résultat dont les DEUX fentes sont valides : la porte a changé un graphe qui était juste`);
  // CONTRÔLE POSITIF DU COMPARATEUR : sans lui, un comparateur qui répondrait toujours « identique »
  // passerait (45c) brillamment. Sur du texte il doit voir bouger EXACTEMENT les modes qui coercent.
  const bougent = MODES.filter((m) => viz.vizSansPorte(m, COLS, TXT, "q", "").outerHTML !== viz.vizElement(m, COLS, TXT, "q", "").outerHTML);
  exiger(bougent.length === coercantes.length && bougent.every((m) => coercantes.includes(m)),
    `(45c-instrument) le comparateur voit bouger [${bougent.join(", ")}] au lieu des ${coercantes.length} modes qui coercent [${coercantes.join(", ")}] : (45c) ne prouverait rien`);

  // ---- (c-bis) L'ABSCISSE EST L'AUTRE FENTE, ET LA PORTE NE LA CONFOND PAS AVEC UNE CATÉGORIE ----
  // Le constat de la clé sur « line » est une faute d'ABSCISSE, et une porte posée sur la seule
  // ordonnée l'aurait fermée par accident : ici l'ordonnée est NUMÉRIQUE et seule l'abscisse est du
  // texte. NÉGATIF d'abord — sans la porte, les trois points sont empilés sur une abscisse unique.
  const CAT = [["a", 3], ["b", 9], ["c", 1]];
  const abscissantes = MODES.filter((m) => viz.sondage(m).abscisseNumerique);
  exiger(abscissantes.length > 0 && abscissantes.length < MODES.length,
    `(45c-bis-instrument) la sonde d'abscisse ne partage plus les modes (${abscissantes.length} sur ${MODES.length}) : un verdict constant ne mesurerait rien`);
  for (const m of abscissantes) {
    // Le marqueur de survol est un CERCLE sans abscisse tant qu'on n'a pas survolé : on ne lit que les
    // marques réellement POSÉES, sinon le témoin compterait un point que personne ne voit.
    const empiles = trouver(viz.vizSansPorte(m, COLS, CAT, "", ""), (n) => n.tagName === "CIRCLE").map((n) => n.attributes.cx).filter((v) => v !== undefined);
    exiger(empiles.length === 3 && new Set(empiles).size === 1,
      `(45c-bis-négatif) « ${m} » sans la porte n'empile plus ses trois points sur une abscisse unique (${JSON.stringify(empiles)}) : le positif ne prouverait rien`);
    const t = viz.vizElement(m, COLS, CAT, "", "").textContent;
    exiger(/Graphe refusé|Chart refused/.test(t) && t.includes("host") && /abscisse|X axis/.test(t),
      `(45c-bis) « ${m} » trace encore une abscisse textuelle sous une ordonnée numérique, ou son refus ne nomme pas l'abscisse : « ${t.slice(0, 160)} »`);
  }
  // ET LA PORTE N'EST PAS GOURMANDE : une abscisse textuelle est une CATÉGORIE parfaitement légitime
  // partout ailleurs. Aucun des autres modes n'est refusé sur le même jeu — la jauge comprise, dont la
  // colonne 0 est une ÉCHELLE et non une position, et qui reçoit ici son entrée la plus naturelle.
  for (const m of MODES.filter((x) => !abscissantes.includes(x))) {
    const t = viz.vizElement(m, COLS, CAT, "", "").textContent;
    exiger(!/Graphe refusé|Chart refused/.test(t),
      `(45c-bis) « ${m} » refuse une abscisse CATÉGORIELLE, que sa sonde dit pourtant ne pas placer par la valeur : « ${t.slice(0, 160)} »`);
  }

  // ---- (d) LE REFUS PREND LA PLACE DU GRAPHE, JAMAIS CELLE DE L'ISSUE ----
  // Un refus sans issue serait une impasse : la barre de réglage reste au-dessus, donc l'exploitant
  // peut désigner une autre ordonnée sans quitter la vue.
  const noeuds = viz.noeudsDeVizReglee("bar", COLS, TXT, "", "", 0, () => {});
  const texteEntier = noeuds.map((n) => n.textContent).join(" | ");
  exiger(noeuds.length >= 2 && /Graphe refusé|Chart refused/.test(texteEntier) && trouver({ children: noeuds }, (n) => n.tagName === "SELECT").length >= 2,
    `(45d) le refus par défaut ne laisse pas la barre de réglage au-dessus : l'exploitant n'a aucune issue — « ${texteEntier.slice(0, 160)} »`);

  // ---- (e) ZÉRO LIGNE N'EST PAS LA VALEUR ZÉRO ----
  const jaugeVide = viz.vizElement("gauge", COLS, [], "", "").textContent.replace(/\s+/g, " ");
  exiger(!/0\s*\/\s*1/.test(jaugeVide) && /aucune donnée|no data/i.test(jaugeVide),
    `(45e) la jauge affirme encore un rapport sur un résultat SANS AUCUNE ligne : « ${jaugeVide} »`);
  // NÉGATIF : la ligne d'avant, reconstituée à la main, fabriquait bien les deux termes.
  const avant = (rows) => { const raw = rows.length ? Number(rows[0][rows[0].length - 1]) : 0; const v = Number.isFinite(raw) ? raw : 0; const m = Math.max(1, v); const p = Math.pow(10, Math.floor(Math.log10(m))); return `${v} / ${Math.ceil(m / p) * p}`; };
  exiger(avant([]) === "0 / 1", `(45e-négatif) la reconstitution du calcul d'avant ne rend plus « 0 / 1 » sur zéro ligne (« ${avant([])} ») : (45e) ne prouverait pas qu'un rapport était fabriqué`);

  // ---- (f) AUCUN MODULE NE CONTOURNE LA PORTE ----
  // La propriété tenue : hors de `viz.js`, le dispatcher NU n'est nommé nulle part — le seul chemin
  // vers une représentation passe donc par `vizElement`, y compris l'aperçu d'un instantané partagé,
  // qui n'a aucune barre de réglage. DANS `viz.js`, les seules lignes qui l'appellent sont la porte
  // elle-même et le sondage : toute autre ligne qui le nommerait fait rougir ce témoin.
  const ailleurs = readdirSync(WEB).filter((f) => f.endsWith(".js") && f !== "viz.js")
    .filter((f) => readFileSync(path.join(WEB, f), "utf8").includes("vizSansPorte"));
  exiger(ailleurs.length === 0, `(45f) ${ailleurs.join(", ")} nomme(nt) le dispatcher NU : un chemin contourne la porte et rendrait un graphe faux sans un mot`);
  const appels = source.split("\n").map((l, i) => [i + 1, l]).filter(([, l]) => /(?<!function )vizSansPorte\s*\(/.test(l));
  // L'ENCLOS EST LU, PAS DEVINÉ À UN MOT DE LA LIGNE. Ce témoin exigeait que chaque ligne d'appel porte
  // le texte « refus ? » — la forme que la porte avait alors. La PROPRIÉTÉ tenue n'a jamais été ce
  // texte : c'est que les seuls appelants du dispatcher nu soient la PORTE et le SONDAGE. La porte s'est
  // dédoublée le 2026-08-27 (une seconde décision lit le RENDU, elle ne pouvait plus tenir dans un
  // ternaire), le texte a disparu, la propriété non. On dérive donc la FONCTION qui contient chaque
  // appel — déclaration la plus proche au-dessus, colonne zéro — et on exige que ce soient exactement
  // ces deux-là. Le plafond de DEUX appels ne bouge pas, et un appel posé dans une troisième fonction,
  // que l'ancienne forme aurait laissé passer s'il portait le mot « refus ? », rougit désormais.
  const declarations = source.split("\n").map((l, i) => [i + 1, (l.match(/^function ([\w$]+)\s*\(/) || [])[1]]).filter(([, n]) => n);
  const fonctionDe = (ligne) => { let nom = "(hors fonction)"; for (const [n, f] of declarations) { if (n <= ligne) nom = f; else break; } return nom; };
  const enclos = appels.map(([n]) => fonctionDe(n));
  exiger(declarations.length > 20 && fonctionDe(appels.length ? appels[0][0] : 1) !== "(hors fonction)",
    `(45f-instrument) la lecture des déclarations de web/viz.js est cassée (${declarations.length} vue(s)) : l'enclos jugé ci-dessous ne vaudrait rien`);
  exiger(appels.length === 2 && enclos.includes("vizElement") && enclos.includes("rendreEnSonde") && new Set(enclos).size === 2,
    `(45f) les appels au dispatcher NU dans web/viz.js ne sont plus les deux attendus (la porte \`vizElement\`, le sondage \`rendreEnSonde\`) : ${JSON.stringify(appels.map(([n, l], k) => n + " dans " + enclos[k] + " : " + l.trim().slice(0, 60)))}`);

  // ---- (g) LE REFUS EXISTE DANS LES DEUX LANGUES, ET IL NOMME LA COLONNE DANS LES DEUX ----
  const deuxLangues = viz.refusDeRepresentation("bar", COLS, TXT);
  exiger(deuxLangues && deuxLangues.fr && deuxLangues.en && deuxLangues.fr !== deuxLangues.en
    && deuxLangues.fr.includes("sev") && deuxLangues.en.includes("sev"),
    `(45g) le refus ne porte pas deux textes distincts nommant la colonne : ${JSON.stringify(deuxLangues)}`);

  console.log(`[graphe-refuse] les ${MODES.length} représentations du dispatcher sont partagées PAR LE SONDAGE, pas par une liste : ${coercantes.length} ramènent leur ORDONNÉE à un nombre (${coercantes.join(", ")}), ${libres.length} non (${libres.join(", ")}), et ${abscissantes.length} placent leurs lignes selon l'ABSCISSE et la ramènent à un nombre (${abscissantes.join(", ")}) — la faute que la clé attribuait à « line » est celle-là, et une porte posée sur la seule ordonnée l'aurait fermée par accident : sous une ordonnée NUMÉRIQUE et une abscisse textuelle, « line » empilait toujours ses trois points sur une abscisse unique, ce qui est reproduit ici. Les autres modes, dont la jauge (qui lit sa colonne 0 comme une ÉCHELLE et non comme une position), ne sont PAS refusés sur la même donnée : une abscisse textuelle y est une catégorie légitime. Sans la porte, les six figures fausses relevées sur banc sont TOUTES reproduites ici à leur signature exacte — barres à 0 % avec le mot à côté, courbe écrasée sur un point, jauge « 0 / 1 », camembert qui annonce une absence sur trois lignes, grille de chaleur vide — et l'aveu d'« histogram » se révèle partiel : sur une colonne MÉLANGÉE il rendait la valeur textuelle en barre de hauteur zéro. Avec la porte, chacune est REFUSÉE et le refus nomme la colonne, le compte et un exemple, dans les deux langues ; une colonne SANS AUCUNE valeur reçoit une phrase différente, qui ne compte pas « 0 sur 0 » ; la barre de réglage reste au-dessus du refus, donc il y a une issue ; la jauge n'affirme plus « 0 / 1 » sur zéro ligne ; et aucun module ne nomme le dispatcher NU. NON-RÉGRESSION : sur un résultat dont les DEUX fentes sont valides, les ${MODES.length} modes rendent un balisage BYTE-IDENTIQUE à celui d'avant la porte, et le comparateur qui l'établit voit bouger exactement les ${coercantes.length} modes qui coercent dès qu'on lui donne du texte. CE QUE CE TÉMOIN NE TIENT PAS : l'encre réellement peinte (section 0 — la largeur nulle est lue sur le style EN LIGNE) et les panneaux semés par le démon, dont les requêtes vivent hors de web/.`);
}

// ---------------------------------------------------------------------------------------------
// 47. LE GESTE QUI CHANGE QUI PEUT LIRE UNE VUE DEMANDE, ET NOMME CE QUI VA SE PASSER (`P11.13-b`).
//     CE QUE LA GARDE DE ROUTES NE POUVAIT PAS DIRE. `check_sensitive_routes_are_confirmed.py` déclarait
//     cet appel « confirmé » — mesuré le 2026-08-26 : non par une confirmation à lui, mais parce que son
//     ANCÊTRE `initDashboards` contient le `confirmModal(` du bouton « supprimer la vue », dont la
//     fonction (lignes 888-893 alors) ne contient pas cet appel. Une confirmation de VOISIN, lue par une
//     remontée de portées ; la garde grep des NOMS, elle ne peut pas voir qu'aucune fenêtre ne s'ouvre.
//     Ce témoin-ci JOUE le chemin et regarde ce qui est POSÉ et ce qui PART.
//     (a) L'INSTRUMENT D'ABORD : la vue servie est PRIVÉE et le bouton est atteignable ; sans cela le
//         geste exercé ne serait pas celui qui expose.
//     (b) LA PORTE EST FERMANTE : la fenêtre s'ouvre, elle NOMME la conséquence dans sa ligne dédiée, et
//         un REFUS ne laisse partir AUCUNE écriture. C'est le sens qui compte : une confirmation qu'on
//         peut contourner ne vaut rien, et une écriture déjà partie ne se rattrape pas.
//     (c) LA PORTE EST PASSANTE : validée, l'écriture part, et elle porte la visibilité demandée.
//     (d) LA CONSÉQUENCE SUIT LA DIRECTION : partager et dé-partager ne disent pas la même chose. Une
//         phrase unique passerait (b) et (c) en mentant à l'un des deux sens.
//     CE QUE CE TÉMOIN NE TIENT PAS : ni la mise en page ni le style de la fenêtre ; ni ce que le démon
//     fait de l'écriture (il n'est pas là) ; et rien des deux autres gestes du même bandeau (créer et
//     renommer une vue), qui héritent de la même remontée de portées sans qu'on leur demande rien —
//     créer et renommer n'exposent pas ce qui était privé, et ce témoin ne prétend pas les couvrir.
// ---------------------------------------------------------------------------------------------
{
  const url42 = (f) => pathToFileURL(path.join(WEB, f)).href;
  const modDash = await import(url42("dashboards.js"));
  const { S } = await import(url42("state.js"));

  const tic = () => new Promise((r) => setTimeout(r, 0));
  const laisserTourner = async (n = 20) => { for (let i = 0; i < n; i++) await tic(); };
  const fenetre = () => document.body.children.filter((c) => c.classList && c.classList.contains("modal-ov") && !c.classList.contains("out")).pop();
  const cueillir42 = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir42(c, pred, acc)); return acc; };
  const parClasse = (racine, cl) => cueillir42(racine, (e) => e.classList && e.classList.contains(cl), [])[0] || null;

  const etatVue = { views: [{ id: 7, name: "Production", owner: "hugo", visibility: "private", dashboards: 2 }], me: "hugo", role: "admin" };
  const ecritures = [];
  const boutonPartage = new Element("button"), selecteurVue = new Element("select");
  const hotes42 = { "#view-share": boutonPartage, "#view": selecteurVue };
  const qsOrigine = document.querySelector, fetchOrigine = globalThis.fetch;
  const etatOrigine = { role: S.viewsRole, me: S.viewsMe, liste: S.viewList };
  document.querySelector = (sel) => (Object.prototype.hasOwnProperty.call(hotes42, sel) ? hotes42[sel] : new Element("div"));
  globalThis.fetch = async (u, o) => {
    const url = String(u), methode = (o && o.method) || "GET";
    if (methode !== "GET") { ecritures.push(methode + " " + url + " " + ((o && o.body) || "")); return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true }) }; }
    if (url.includes("/api/views")) return { ok: true, status: 200, text: async () => JSON.stringify(etatVue) };
    return { ok: true, status: 200, text: async () => JSON.stringify({}) };
  };
  try {
    modDash.initDashboards();
    await laisserTourner();
    // La vue est CHOISIE par le sélecteur, comme un exploitant la choisit : c'est ce geste qui décide
    // quelle vue le bouton de partage porte, et sans lui le bouton reste masqué.
    selecteurVue.value = "7";
    selecteurVue.dispatchEvent({ type: "change" });
    await laisserTourner();

    // (a) INSTRUMENT.
    exiger(S.viewList.length === 1 && S.viewList[0].visibility === "private",
      `(47a) instrument : la vue servie n'est pas celle attendue (${JSON.stringify(S.viewList)}) — le geste exercé ne serait pas celui qui EXPOSE ce qui était privé`);
    exiger(!boutonPartage.hidden, "(47a) instrument : le bouton de partage est masqué pour le propriétaire admin de la vue — le chemin n'est pas atteignable, rien de ce qui suit ne se mesure");

    // (b) REFUSÉE : une fenêtre est posée, elle NOMME la conséquence, et rien ne part.
    const avantRefus = ecritures.length;
    boutonPartage.dispatchEvent({ type: "click" });
    await laisserTourner();
    const ov1 = fenetre();
    exiger(!!ov1, "(47b) aucun geste de confirmation n'est posé : basculer une vue PRIVÉE en vue d'équipe part sans rien demander — la garde de routes la croyait pourtant confirmée");
    const csq = ov1 ? parClasse(ov1, "modal-consequence") : null;
    exiger(!!csq && String(csq.textContent).trim().length > 20,
      `(47b) la fenêtre ne porte pas de ligne de CONSÉQUENCE lisible (« ${csq && csq.textContent} ») : « confirmer » sans dire ce qui va se passer ne vaut pas mieux que ne rien demander`);
    exiger(!!csq && /Production/.test(csq.textContent), `(47b) la conséquence ne nomme pas la vue concernée : « ${csq && csq.textContent} »`);
    const annuler = ov1 ? parClasse(ov1, "m-cancel") : null;
    exiger(!!annuler, "(47b) instrument : la fenêtre n'offre pas de sortie — le sens NÉGATIF ne peut pas être joué");
    if (annuler) annuler.onclick();
    await laisserTourner();
    exiger(ecritures.length === avantRefus,
      `(47b) une confirmation REFUSÉE laisse tout de même partir l'écriture (${JSON.stringify(ecritures.slice(avantRefus))}) : la fenêtre est un décor, pas une porte`);

    // (c) VALIDÉE : l'écriture part, avec la visibilité demandée.
    const nEcrituresAvantPartage = ecritures.length;
    boutonPartage.dispatchEvent({ type: "click" });
    await laisserTourner();
    const ov2 = fenetre();
    const csqPartage = ov2 ? String(parClasse(ov2, "modal-consequence").textContent) : "";
    exiger(!!ov2 && !!ov2.children[0] && !!ov2.children[0].children[0], "(47c) instrument : la fenêtre posée n'a pas la forme attendue, le sens POSITIF ne peut pas être joué");
    // Ce que la route SERT change avec l'écriture : le geste rappelle `loadViews`, et la vue qui revient
    // est partagée. Sans cela, (d) rejouerait la même direction en croyant en jouer une autre.
    etatVue.views = [{ id: 7, name: "Production", owner: "hugo", visibility: "shared", dashboards: 2 }];
    if (ov2 && ov2.children[0] && ov2.children[0].children[0]) ov2.children[0].children[0].onsubmit({ preventDefault() {} });
    await laisserTourner();
    // `P11.22-a` — MÊME CORRECTION QU'EN (40c) : la tranche du geste, jamais la dernière ligne d'un
    // journal partagé qu'un envoi différé peut coiffer.
    const partDuGeste = ecritures.slice(nEcrituresAvantPartage);
    const derniere = partDuGeste.filter((e) => /POST \/api\/views\/7/.test(e)).at(-1) || "";
    exiger(partDuGeste.some((e) => /POST \/api\/views\/7/.test(e)) && /"visibility":"shared"/.test(derniere),
      `(47c) une confirmation VALIDÉE ne fait pas partir le partage attendu (dernière écriture : « ${derniere} ») — la porte est fermée dans les deux sens, ce qui est aussi un défaut`);

    // (d) LA CONSÉQUENCE SUIT LA DIRECTION.
    exiger(S.viewList[0] && S.viewList[0].visibility === "shared",
      `(47d) instrument : après l'écriture la vue servie n'est pas revenue PARTAGÉE (${JSON.stringify(S.viewList)}) — la seconde direction ne serait pas jouée`);
    boutonPartage.dispatchEvent({ type: "click" });
    await laisserTourner();
    const ov3 = fenetre();
    const csqRetrait = ov3 ? String(parClasse(ov3, "modal-consequence").textContent) : "";
    const annuler3 = ov3 ? parClasse(ov3, "m-cancel") : null;
    if (annuler3) annuler3.onclick();
    await laisserTourner();
    exiger(csqRetrait.trim().length > 20 && csqRetrait !== csqPartage,
      `(47d) partager et RENDRE PRIVÉ annoncent la MÊME conséquence (« ${csqRetrait} ») : l'une des deux phrases ment sur ce qui va se passer`);
  } finally {
    document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine;
    S.viewsRole = etatOrigine.role; S.viewsMe = etatOrigine.me; S.viewList = etatOrigine.liste;
    document.body.children.filter((c) => c.classList && c.classList.contains("modal-ov")).forEach((c) => c.remove());
  }

  console.log("[partage-de-vue] basculer une vue entre PRIVÉE et partagée avec l'équipe passe désormais par la confirmation partagée qui NOMME sa conséquence, lue dans le démon (`views_list` sert la vue à tous ; `dash_list` filtre chaque tableau de bord sur SA propre visibilité — partager la vue ne partage pas les tableaux de bord privés). Refusée, aucune écriture ne part ; validée, le partage part avec la visibilité demandée ; et les deux directions n'annoncent pas la même chose. La garde de routes déclarait cet appel confirmé par la portée de son VOISIN destructif : elle grep des noms, ce témoin joue le chemin.");
}

// ---------------------------------------------------------------------------------------------
// 44. UN INVENTAIRE QUI ÉCARTE LE DIT — AVEC LES BORNES DU DÉMON, PAS AVEC LES SIENNES — ET UN
//     PRODUCTEUR N'ARRIVE JAMAIS EN BLANC (`P11.18-y`, `P11.16-a`).
//
//     CE QUI EST MESURÉ, ET POURQUOI LE TÉMOIN LIT LE DÉMON. `/api/sources` ne rend pas « les
//     sources » : il rend celles que DEUX bornes laissent passer — la fenêtre (`FENETRE_INVENTAIRE_S`,
//     déclarée dans `daemon/src/handlers/freshness.rs`) et un volume minimal (`HAVING SUM(n)>=N` dans
//     la requête d'inventaire de `daemon/src/handlers/sources.rs`). La route ne PUBLIE ni l'une ni
//     l'autre : pour les nommer à l'écran, la console doit les écrire, et une copie écrite finit par
//     diverger. Ce témoin est ce qui l'en empêche : il DÉRIVE les deux valeurs du démon et exige que le
//     texte rendu les nomme. Le jour où le démon bouge une borne sans que la vue suive, il rougit.
//     (a) LES BORNES, dérivées puis cherchées dans le TEXTE de l'arbre construit ; l'instrument se
//         valide d'abord (les deux dérivations doivent trouver quelque chose, et l'inventaire doit
//         VRAIMENT borner sa lecture par la constante lue dans l'autre fichier), et le témoin NÉGATIF
//         rejoue le même prédicat sur le texte dont le nombre a été changé : sans lui, un prédicat qui
//         ne lirait pas le chiffre passerait pour une preuve.
//     (b) UNE LISTE VIDE DIT SES BORNES ELLE AUSSI. C'est le seul cas où un lecteur peut conclure « il
//         n'y a rien » alors que la réponse est « rien n'a franchi les bornes » : la phrase est donc
//         posée avant le tableau, pas dans la légende, qui ne paraît qu'avec des lignes.
//     (c) « dormant » NE SE DIT PLUS « aucune donnée observée ». Mesuré dans `sources.rs` : une source
//         entre avec `last_seen` nul par la porte des marquages (`or_insert((0, 0))`), qui ne sait pas
//         si la source n'a rien poussé ou si son volume reste sous le seuil — le mot RECOUVRE deux
//         faits. Le témoin exige que la raison le dise, et le témoin inverse (un état non dormant)
//         interdit qu'une version qui collerait la phrase partout passe pour une correction.
//     (d) `P11.16-a` — LE QUATRIÈME CAS DU PRODUCTEUR. Deux booléens décidaient de trois cas ; le
//         premier rendait `raison_attendue || ''`, donc un BLANC dès qu'une charge utile déclare le
//         producteur connu par construction sans en rendre le nom (démon antérieur, champ renommé) —
//         exactement le blanc que ce bloc refuse ailleurs. Témoin inverse : avec le nom, c'est le NOM
//         qui est rendu, pas l'aveu.
//     (e) `P11.16-a` — LE RENVOI DE LA FRAÎCHEUR NE PROMET PLUS CE QUE L'INVENTAIRE NE PORTE PAS.
//         L'inventaire est bâti sur `event_rollup` : il ne liste QUE des sources d'événements, alors
//         que la fraîcheur rend aussi des instantanés et des métriques. Le compte des flux d'un autre
//         genre est DÉRIVÉ des flux rendus (aucune table de genres n'est écrite dans la console), et le
//         témoin inverse — une charge utile 100 % événements — interdit la phrase qui compterait
//         toujours.
//     CE QUE CE TÉMOIN NE TIENT PAS, ET IL L'ÉCRIT : il ne dit pas COMBIEN de sources le démon a
//     écartées — la route ne rend que les lignes gardées, et ce nombre n'est dérivable d'aucune charge
//     utile servie à la console ; il lit le TEXTE du démon, pas son exécution (un seuil appliqué
//     ailleurs lui échapperait) ; et il ne voit ni la mise en page ni le style calculé.
// ---------------------------------------------------------------------------------------------
{
  const { renderSourcesInventory } = await import(pathToFileURL(path.join(WEB, "sources.js")).href);
  const { renderFreshnessDetail } = await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const srcRs = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "sources.rs"), "utf8");
  const frRs = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "freshness.rs"), "utf8");
  const cueillir44 = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir44(c, pred, acc)); return acc; };
  const parClasse = (racine, cls) => cueillir44(racine, (e) => e.classList && e.classList.contains(cls), []);
  const motDEtat = (racine, mot) => cueillir44(racine, (e) => e.tagName === "B" && String(e.textContent) === mot, [])[0] || null;

  // (a) L'INSTRUMENT D'ABORD : les deux bornes viennent du DÉMON.
  const mSeuil = srcRs.match(/GROUP BY source HAVING SUM\(n\)>=(\d+)/);
  const mFenetre = frRs.match(/FENETRE_INVENTAIRE_S:\s*i64\s*=\s*(\d+)\s*\*\s*86400/);
  exiger(!!mSeuil, "(44a) instrument : la clause de volume de la requête d'inventaire n'est plus lisible dans `daemon/src/handlers/sources.rs` — les bornes affichées ne sont plus dérivées de rien, et ce témoin ne prouverait plus qu'un texte se ressemble");
  exiger(!!mFenetre, "(44a) instrument : `FENETRE_INVENTAIRE_S` n'est plus lisible dans `daemon/src/handlers/freshness.rs` — la fenêtre affichée n'est plus dérivée");
  exiger(/let cut7 = now_ts - FENETRE_INVENTAIRE_S;/.test(srcRs), "(44a) instrument : l'inventaire ne borne plus sa lecture par `FENETRE_INVENTAIRE_S` — la fenêtre dérivée de `freshness.rs` n'est plus la sienne, et la comparer au texte affiché n'aurait plus de sens");
  const SEUIL = mSeuil ? mSeuil[1] : "";
  const JOURS = mFenetre ? mFenetre[1] : "";
  const nommeLesBornes = (txt) => !!SEUIL && !!JOURS
    && new RegExp("au moins " + SEUIL + " événement").test(txt)
    && new RegExp("les " + JOURS + " derniers jours").test(txt);

  const uneSource = (o) => Object.assign({
    source: "portprobe", expected: true, unexpected: false, in_collectors: true, declaree_par: "ce dépôt",
    raison_attendue: "émise par un fichier livré (collectors/portprobe.sh)", marquage: null,
    cadence_declarable: true, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null,
    cadence_par: null, cadence_le: null, observed_interval_s: null, last_seen: 1000, age_s: 60, n_24h: 10, status: "frais",
  }, o);
  const rendreInventaire = (sources) => { const h = new Element("div"); renderSourcesInventory(h, { ok: true, pipeline_fresh: true, sources }); return h; };

  const roleAvant44 = document.body.className;
  document.body.className = "role-viewer";
  try {
    const plein = rendreInventaire([uneSource({}), uneSource({ source: "vault-custom", in_collectors: false, declaree_par: "l'exploitant", raison_attendue: "déclarée par eve (ts 1700000000)", marquage: { expected: true, updated_by: "eve", updated: 1700000000 } })]);
    const tPlein = texte(plein);
    exiger(nommeLesBornes(tPlein), `(44a) l'inventaire n'écrit pas les DEUX bornes que le démon applique (seuil ${SEUIL} événement(s), fenêtre ${JOURS} jours) : « ${tPlein.slice(0, 400)} »`);
    exiger(/ne peut donc pas le dire/.test(tPlein), `(44a) l'inventaire ne dit pas qu'il IGNORE combien de sources sont écartées — une vue qui tait ce qu'elle ne sait pas se lit comme complète : « ${tPlein.slice(0, 400)} »`);
    // témoin NÉGATIF : le prédicat lit-il vraiment le NOMBRE, ou seulement la phrase qui l'entoure ?
    const mute = tPlein.replace("au moins " + SEUIL + " événement", "au moins " + (Number(SEUIL) + 1) + " événement");
    exiger(mute !== tPlein, "(44a-négatif) instrument : la mutation du nombre n'a rien changé au texte, le témoin négatif ne prouve rien");
    exiger(!nommeLesBornes(mute), "(44a-négatif) le vérificateur ne lit pas le NOMBRE du seuil : un texte qui en nommerait un autre passerait pour dérivé du démon");

    // (b) une liste VIDE dit ses bornes elle aussi.
    const vide = rendreInventaire([]);
    const tVide = texte(vide);
    exiger(/aucune source/.test(tVide), `(44b) instrument : la charge utile vide ne rend pas la liste vide attendue, ce qui suit ne porte pas sur elle : « ${tVide.slice(0, 200)} »`);
    exiger(nommeLesBornes(tVide), `(44b) un inventaire VIDE ne dit pas ce qu'il écarte : « il n'y a rien » et « rien n'a franchi les bornes » s'y lisent pareil — « ${tVide.slice(0, 400)} »`);

    // (c) « dormant » porte sa raison, et lui seul.
    const dormante = rendreInventaire([uneSource({ source: "sonde-discrete", status: "dormant", last_seen: null, age_s: null, n_24h: 0 }), uneSource({})]);
    const bDormant = motDEtat(dormante, "dormant"), bFrais = motDEtat(dormante, "frais");
    exiger(!!bDormant && !!bFrais, "(44c) instrument : les deux mots d'état ne sont pas rendus, la comparaison n'a pas d'objet");
    exiger(bDormant && /soit rien n'est arrivé/.test(bDormant.title || "") && new RegExp("sous le seuil de volume \\(" + SEUIL + " ").test(bDormant.title || ""), `(44c) « dormant » ne dit pas qu'il RECOUVRE deux faits (rien poussé / sous le seuil) : « ${bDormant && bDormant.title} »`);
    exiger(bFrais && !bFrais.title, `(44c) témoin inverse : un état non dormant porte lui aussi la raison — une version qui la collerait partout passerait le témoin précédent (« ${bFrais && bFrais.title} »)`);
    exiger(!/aucune donnée n'a été observée/.test(texte(dormante)), "(44c) la légende affirme encore qu'aucune donnée n'a été OBSERVÉE pour un dormant — c'est faux d'une source qui a poussé sous le seuil");

    // (d) P11.16-a — le producteur n'arrive jamais en blanc.
    const muette = rendreInventaire([uneSource({ source: "capteur-sans-nom", raison_attendue: null, declaree_par: null })]);
    const prodMuet = parClasse(muette, "srcprod")[0];
    exiger(!!prodMuet, "(44d) instrument : la ligne du producteur n'est pas rendue, le blanc ne se mesure pas");
    exiger(prodMuet && String(prodMuet.textContent).trim() !== "", "(44d) une source déclarée dont la route n'a pas rendu le producteur laisse une ligne VIDE sous son nom : un blanc se lit comme une origine évidente");
    exiger(prodMuet && /cette route ne l'a pas nommé/.test(prodMuet.textContent), `(44d) le blanc est comblé par autre chose que l'aveu : « ${prodMuet && prodMuet.textContent} »`);
    exiger(!/aucune déclaration/.test(texte(muette)), "(44d) la colonne « Déclarée » dément le badge de sa propre ligne : une absence de RAISON y est rendue comme une absence de DÉCLARATION");
    const prodNomme = parClasse(rendreInventaire([uneSource({})]), "srcprod")[0];
    exiger(prodNomme && /collectors\/portprobe\.sh/.test(prodNomme.textContent) && !/ne l'a pas nommé/.test(prodNomme.textContent), `(44d) témoin inverse : le producteur NOMMÉ est remplacé par l'aveu — une version qui avouerait toujours passerait le témoin précédent (« ${prodNomme && prodNomme.textContent} »)`);

    // (e) P11.16-a — la fraîcheur ne renvoie plus vers un producteur que l'inventaire ne porte pas.
    const flux = (o) => Object.assign({ kind: "event", name: "mail", status: "calme", age_s: 600, last_seen: 1000, n_24h: 96, active_alerts: 0, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: null }, o);
    const nu = (h) => h.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    const mixte = nu(renderFreshnessDetail({ pipeline_fresh: true, feeds: [flux({}), flux({ kind: "snapshot", name: "process", n_hosts: 3 }), flux({ kind: "metric", name: "métriques · 3 séries", series: [] })] }));
    exiger(/2 flux de cette liste qui n'en sont pas/.test(mixte), `(44e) le renvoi vers l'inventaire promet un producteur pour des flux que l'inventaire ne porte pas (instantanés, métriques) : « ${mixte.slice(-600)} »`);
    const quEvenements = nu(renderFreshnessDetail({ pipeline_fresh: true, feeds: [flux({}), flux({ name: "yara" })] }));
    exiger(/tous les flux de cette liste en sont/.test(quEvenements) && !/qui n'en sont pas/.test(quEvenements), `(44e) témoin inverse : la phrase compte des flux d'un autre genre là où il n'y en a aucun — elle n'est pas dérivée des flux rendus : « ${quEvenements.slice(-600)} »`);
  } finally {
    document.body.className = roleAvant44;
  }

  console.log(`[inventaire-perimetre] l'inventaire des sources NOMME les deux bornes qui décident de son contenu — un volume minimal de ${SEUIL} événement(s) sur une fenêtre de ${JOURS} jours — et ces deux nombres sont DÉRIVÉS du démon (clause « HAVING » de la requête d'inventaire, constante de fenêtre), jamais recopiés : le témoin négatif prouve qu'un autre nombre serait vu. Il DIT aussi ce qu'il ignore — combien de sources sont écartées, que la route ne rend pas — et il le dit MÊME sur une liste vide, le seul cas où « il n'y a rien » et « rien n'a franchi les bornes » se confondent. « dormant » ne prétend plus qu'aucune donnée n'a été observée : il avoue recouvrir deux faits, et lui seul porte cette raison. Un producteur connu par construction dont la route ne rend pas le nom ne laisse plus un BLANC sous la source, et la colonne « Déclarée » ne dément plus le badge de sa propre ligne. Enfin la fraîcheur ne renvoie vers l'inventaire que pour les flux qu'il porte, en COMPTANT les autres. Ce que ce témoin NE tient PAS : le nombre de sources écartées (aucune charge utile servie ne le porte) ; il lit le TEXTE du démon, pas son exécution ; et rien de la mise en page ni du style.`);
}

// ---------------------------------------------------------------------------------------------
// 41. UNE VALEUR COUPÉE PORTE SON RECOURS, ET LE RECOURS PART AVEC LA COUPE (`P11.15-a`, `P11.18-b`).
//     CE QUI MANQUAIT, ET POURQUOI ÇA MANQUAIT. Le mécanisme de dépli par cellule est posé dans la
//     fabrique de tableaux depuis le 2026-08-25 ; AUCUN témoin ne le tenait. La raison est écrite en
//     section 0 : le simulacre n'a pas de mise en page, `scrollWidth` et `clientWidth` y sont indéfinis,
//     donc le prédicat « cette cellule déborde » y vaut TOUJOURS faux — un mécanisme entier passait sans
//     être exercé, et la propriété se serait perdue au prochain tableau.
//
//     COMMENT CE TÉMOIN CONTOURNE LA CÉCITÉ, ET CE QU'IL NE PROUVE PAS. Il POSE lui-même les deux
//     largeurs sur les nœuds qu'il fabrique. Il ne prouve donc RIEN de l'encre peinte, rien d'une
//     largeur réelle, rien de ce que la feuille de style impose : il prouve ce que le CODE fait d'une
//     mesure — où il pose le geste, où il refuse de le poser, ce qu'il rend quand la mesure change. La
//     cécité de la section 0 n'est pas fermée par ce témoin ; elle est CONTOURNÉE, et la clause de la
//     section 0 le dit maintenant mot pour mot.
//
//     UNE FAUTE D'INSTRUMENT MESURÉE ET FERMÉE EN CHEMIN (2026-08-26). Le sélecteur de la fabrique
//     (`tbody > tr:not(.rowdetail) > td`) n'était pas lisible par le moteur du simulacre : `:not(…)` ne
//     passait pas sa grammaire d'étape, donc `querySelectorAll` rendait une liste VIDE — sans un mot.
//     Un témoin écrit au-dessus de ce trou aurait mesuré « aucune cellule » et conclu « rien à faire ».
//     L'exclusion est désormais lue, et (41b) exige qu'elle RETIRE des nœuds au lieu de tous les emporter.
//
//     LES SIX PROPRIÉTÉS TENUES : (a) le prédicat et sa borne, dans les deux sens ; (b) le sélecteur ;
//     (c) le geste posé sur ce qui déborde ET SUR RIEN D'AUTRE, les exclusions étant DÉRIVÉES du contenu
//     (une cellule qui porte un contrôle, fût-il imbriqué) et de la table (`.onecol`, `.rowdetail`) ;
//     (d) la valeur emboîtée sans perdre un nœud, le bouton dernier, l'état DIT et un chevron ; (e) le
//     clic qui déplie sur place et s'arrête AVANT la ligne — dont le clic est un pivot —, avec son témoin
//     inverse ; (f) la re-mesure qui lit la BOÎTE et non la cellule, sans quoi le recours disparaîtrait
//     au premier survol ; (g) le retrait qui rend la cellule TELLE QU'ELLE ÉTAIT, infobulle comprise.
// ---------------------------------------------------------------------------------------------
{
  const { marquerLesCellulesTronquees, celluleDeborde } = await import(pathToFileURL(path.join(WEB, "core.js")).href);

  const poserLargeur = (el, contenu, place) => { el.scrollWidth = contenu; el.clientWidth = place; return el; };
  const tableau = (classes) => {
    const hote = document.createElement("div");
    const table = document.createElement("table"); table.className = classes || "qtable";
    const tbody = document.createElement("tbody");
    table.appendChild(tbody); hote.appendChild(table);
    return { hote, table, tbody };
  };
  const ligne = (tbody, cls) => { const tr = document.createElement("tr"); if (cls) tr.className = cls; tbody.appendChild(tr); return tr; };
  const cellule = (tr, contenu, contenuPx, placePx, titre) => {
    const td = document.createElement("td");
    if (Array.isArray(contenu)) contenu.forEach((n) => td.appendChild(n)); else td.textContent = contenu;
    if (titre) td.title = titre;
    tr.appendChild(td);
    return poserLargeur(td, contenuPx, placePx);
  };
  const laBoite = (td) => (td.childNodes || []).find((n) => n.classList && n.classList.contains("plval")) || null;
  const lesBoutons = (td) => (td.childNodes || []).filter((n) => n.tagName === "BUTTON" && n.classList && n.classList.contains("plmore"));

  // (41a) LE PRÉDICAT, DANS LES DEUX SENS, ET SA BORNE.
  exiger(celluleDeborde(document.createElement("td")) === false,
    "(41a) instrument : une cellule SANS aucune mesure est déclarée débordante — le geste se poserait au hasard sur tout arbre sans mise en page, et tout ce que ce témoin observe ensuite serait un accident");
  exiger(celluleDeborde(poserLargeur(document.createElement("td"), 400, 200)) === true,
    "(41a) instrument : une cellule dont le contenu fait le double de sa place n'est PAS vue comme débordante — la mesure posée à la main n'atteint pas le prédicat, et le témoin ne mesurerait rien");
  exiger(celluleDeborde(poserLargeur(document.createElement("td"), 201, 200)) === false,
    "(41a) la borne du prédicat a bougé : UN pixel de débordement — l'arrondi sous-pixel d'un rendu ordinaire — suffit désormais à équiper une cellule qui tient dans sa place");
  exiger(celluleDeborde(poserLargeur(document.createElement("td"), 202, 200)) === true,
    "(41a) la borne du prédicat a bougé dans l'autre sens : deux pixels de débordement ne déclenchent plus le geste");

  // Le tableau exercé. Sept cellules, dont trois seulement doivent recevoir le geste.
  const t = tableau();
  const rangee = ligne(t.tbody);
  const aChemin = cellule(rangee, "/var/log/audit/audit.log.1.gz", 400, 200);
  const bCourte = cellule(rangee, "ok", 150, 200);
  const g1 = document.createElement("b"); g1.textContent = "web-01";
  const g2 = document.createElement("span"); g2.className = "muted"; g2.textContent = "· 3 min";
  const gStructuree = cellule(rangee, [g1, g2], 400, 200);
  const texteAvant = gStructuree.textContent;
  const rControles = ligne(t.tbody);
  const cBouton = cellule(rControles, [], 400, 200);
  const btnDeLaVue = document.createElement("button"); btnDeLaVue.textContent = "Éditer"; cBouton.appendChild(btnDeLaVue);
  const cImbrique = cellule(rControles, [], 400, 200);
  const enveloppe = document.createElement("span"); const lien = document.createElement("a"); lien.textContent = "pivoter";
  enveloppe.appendChild(lien); cImbrique.appendChild(enveloppe);
  const rDetail = ligne(t.tbody, "rowdetail");
  const dDetail = cellule(rDetail, "le détail d'un drilldown, qui s'enroule déjà", 400, 200);
  const rTitre = ligne(t.tbody);
  const eTitre = cellule(rTitre, "un message très long", 400, 200, "l'infobulle que la vue a écrite");

  // (41b) LE SÉLECTEUR : L'EXCLUSION RETIRE, ELLE N'EMPORTE PAS TOUT.
  const toutes = t.table.querySelectorAll("tbody > tr > td");
  const jugees = t.table.querySelectorAll("tbody > tr:not(.rowdetail) > td");
  exiger(toutes.length === 7, `(41b) instrument : le simulacre rend ${toutes.length} cellule(s) au lieu des 7 construites — l'arbre exercé n'est pas celui qui est décrit`);
  exiger(jugees.length === 6 && !jugees.includes(dDetail),
    `(41b) instrument : « :not(.rowdetail) » n'écarte pas exactement la ligne de détail (${jugees.length} cellule(s) retenues sur ${toutes.length}) — une exclusion qui rend ZÉRO nœud, comme une qui n'écarte rien, ferait passer la suite pour une mesure`);

  // (41c) LE GESTE EST POSÉ SUR CE QUI DÉBORDE, ET SUR RIEN D'AUTRE.
  const posees = marquerLesCellulesTronquees(t.table);
  exiger(posees === 3, `(41c) ${posees} cellule(s) équipées au lieu de 3 : le recours n'est pas posé là où la valeur est coupée, ou il est posé là où elle ne l'est pas`);
  for (const [td, quoi] of [[aChemin, "une valeur plus large que sa place"], [gStructuree, "une valeur faite de plusieurs nœuds"], [eTitre, "une valeur qui portait déjà une infobulle"]]) {
    exiger(td.classList.contains("plcut") && lesBoutons(td).length === 1, `(41c) ${quoi} n'a pas reçu le geste (marque « plcut », un bouton de dépli)`);
  }
  for (const [td, quoi] of [
    [bCourte, "une cellule qui TIENT dans sa place"],
    [cBouton, "une cellule qui porte un contrôle — elle porte des gestes à faire, pas une valeur à lire"],
    [cImbrique, "une cellule dont le contrôle est IMBRIQUÉ — l'exclusion se dérive du CONTENU, jamais du nom d'une colonne"],
    [dDetail, "la ligne de détail d'un drilldown, qui s'enroule déjà"],
  ]) {
    exiger(!td.classList.contains("plcut") && lesBoutons(td).length === 0 && !td.getAttribute("title"), `(41c) ${quoi} a reçu le geste de dépli`);
  }
  exiger(aChemin.getAttribute("title") === "/var/log/audit/audit.log.1.gz",
    `(41c) le recours immédiat — la valeur ENTIÈRE au survol, sans aucun geste — n'est pas posé : « ${aChemin.getAttribute("title")} »`);
  exiger(eTitre.getAttribute("title") === "l'infobulle que la vue a écrite",
    "(41c) la fabrique a ÉCRASÉ l'infobulle qu'une vue avait écrite : la vue en sait plus qu'elle sur ce qu'elle affiche");

  // (41d) LA VALEUR EST EMBOÎTÉE, PAS PERDUE — ET LE BOUTON DIT SON ÉTAT.
  const boite = laBoite(gStructuree), btn = lesBoutons(gStructuree)[0];
  exiger(!!boite, "(41d) la valeur n'a pas reçu sa propre boîte (`P11.18-b`) : ce qu'un enfant de niveau BLOC met en ligne repasserait sous le bouton");
  exiger(!!boite && boite.childNodes.length === 2 && boite.childNodes[0] === g1 && boite.childNodes[1] === g2,
    "(41d) la boîte de valeur ne contient pas, dans leur ordre, les nœuds MÊMES que la vue avait construits");
  exiger(gStructuree.childNodes.length === 2 && gStructuree.childNodes[0] === boite && gStructuree.childNodes[1] === btn,
    "(41d) la cellule ne range pas exactement [boîte de valeur, bouton] : le bouton doit rester le DERNIER enfant, la valeur s'arrêtant où sa place commence");
  exiger(gStructuree.textContent === texteAvant, `(41d) le texte de la cellule a CHANGÉ en recevant le geste (« ${gStructuree.textContent} » au lieu de « ${texteAvant} ») : le recours ajouterait du bruit à la valeur`);
  exiger(btn.getAttribute("type") === "button", "(41d) le bouton de dépli n'est pas typé : dans un formulaire il vaudrait « submit »");
  exiger(btn.getAttribute("aria-expanded") === "false", `(41d) le bouton ne DIT pas son état (aria-expanded = ${btn.getAttribute("aria-expanded")}) : le dépli partagé n'est pas celui qui a été employé`);
  exiger(/<svg/.test(btn.innerHTML), "(41d) le bouton ne porte aucun chevron : la marque de l'état tiendrait à la seule couleur");

  // (41e) LE CLIC DÉPLIE SUR PLACE, ET IL S'ARRÊTE AVANT LA LIGNE.
  let clicsDeLaLigne = 0;
  rangee.onclick = () => { clicsDeLaLigne++; };
  rangee.addEventListener("click", () => { clicsDeLaLigne++; });
  btn.click();
  exiger(gStructuree.classList.contains("plopen") && btn.getAttribute("aria-expanded") === "true", "(41e) le clic du bouton ne déplie pas la cellule sur place");
  exiger(clicsDeLaLigne === 0, `(41e) le clic du bouton a atteint la LIGNE (${clicsDeLaLigne} rappel(s)) : lire une valeur ferait changer de vue`);
  btn.click();
  exiger(!gStructuree.classList.contains("plopen") && btn.getAttribute("aria-expanded") === "false", "(41e) le second clic ne replie pas la cellule : le bouton n'ouvre et ne referme pas");
  exiger(clicsDeLaLigne === 0, `(41e) le clic de repli a atteint la LIGNE (${clicsDeLaLigne} rappel(s))`);
  gStructuree.click();
  exiger(clicsDeLaLigne === 2, `(41e) témoin inverse : le clic de la CELLULE n'atteint plus la ligne (${clicsDeLaLigne} rappel(s) au lieu de 2) — l'arrêt ne serait pas propre au bouton, il aurait tué le pivot de la ligne`);

  // (41f) LA RE-MESURE LIT LA BOÎTE, PAS LA CELLULE.
  // Ce qu'un navigateur rend APRÈS le marquage : la boîte coupe ce qui dépasse, donc la CELLULE ne
  // déborde plus ; la boîte, elle, déborde toujours. C'est le comportement d'AVANT, reconstitué à la
  // main : une fabrique qui mesurerait la cellule retirerait le recours au premier survol.
  for (const td of [aChemin, gStructuree, eTitre]) { poserLargeur(td, 200, 200); poserLargeur(laBoite(td), 400, 200); }
  exiger(celluleDeborde(aChemin) === false && celluleDeborde(laBoite(aChemin)) === true,
    "(41f) instrument : la cellule marquée et sa boîte rendent le MÊME verdict de débordement — le choix de ce qui est mesuré ne déciderait de rien, et (41f) ne prouverait pas ce qu'il annonce");
  const secondePasse = marquerLesCellulesTronquees(t.table);
  exiger(secondePasse === 0, `(41f) une seconde passe a re-équipé ${secondePasse} cellule(s) : le geste se poserait deux fois sur la même valeur`);
  for (const [td, quoi] of [[aChemin, "un chemin de fichier"], [gStructuree, "une valeur à plusieurs nœuds"], [eTitre, "un message long"]]) {
    exiger(td.classList.contains("plcut") && lesBoutons(td).length === 1, `(41f) la seconde passe a RETIRÉ le recours de ${quoi}, toujours coupé : la fabrique se mesure elle-même au lieu de mesurer la valeur`);
  }

  // (41g) LE RETRAIT REND LA CELLULE TELLE QU'ELLE ÉTAIT.
  for (const td of [gStructuree, eTitre]) { poserLargeur(td, 150, 200); poserLargeur(laBoite(td), 150, 200); }
  const troisiemePasse = marquerLesCellulesTronquees(t.table);
  exiger(troisiemePasse === 0, `(41g) la passe qui RETIRE le geste en a compté ${troisiemePasse} comme posé(s) : le compte rendu ne dit pas ce qui s'est passé`);
  exiger(!gStructuree.classList.contains("plcut") && lesBoutons(gStructuree).length === 0 && laBoite(gStructuree) === null,
    "(41g) une valeur qui TIENT de nouveau dans sa place garde son bouton de dépli et sa boîte : le recours survivrait à la coupe qu'il servait");
  exiger(gStructuree.childNodes.length === 2 && gStructuree.childNodes[0] === g1 && gStructuree.childNodes[1] === g2,
    "(41g) les nœuds que la vue avait construits ne sont pas revenus à leur rang dans la cellule : le retrait en perd ou en réordonne");
  exiger(!gStructuree.getAttribute("title"),
    `(41g) l'infobulle POSÉE PAR LA FABRIQUE survit à la coupe qu'elle servait (« ${gStructuree.getAttribute("title")} ») : elle répète alors, au survol, un texte entièrement lisible`);
  exiger(!eTitre.classList.contains("plcut") && eTitre.getAttribute("title") === "l'infobulle que la vue a écrite",
    `(41g) témoin inverse : en retirant son geste, la fabrique a emporté l'infobulle de la VUE (« ${eTitre.getAttribute("title")} ») — elle ne l'avait pas posée, elle n'a pas à la reprendre`);
  exiger(aChemin.classList.contains("plcut") && lesBoutons(aChemin).length === 1,
    "(41g) la cellule dont la valeur DÉBORDE toujours a perdu son recours dans la même passe : le retrait ne suit pas la mesure, il suit la passe");

  // (41h) LES TABLEAUX HORS MESURE SONT DÉRIVÉS, PAS ÉNUMÉRÉS.
  const unSeulCol = tableau("qtable onecol");
  const cUnCol = cellule(ligne(unSeulCol.tbody), "une ligne longue qui défile déjà dans sa carte", 400, 200);
  exiger(marquerLesCellulesTronquees(unSeulCol.table) === 0 && !cUnCol.classList.contains("plcut"),
    "(41h) un tableau à une colonne — dont la cellule est DÉ-plafonnée et défile — a reçu le geste : le recours y masquerait une valeur déjà lisible");
  const hote = document.createElement("div");
  const normal = tableau(), plat = tableau("qtable onecol");
  const cNormal = cellule(ligne(normal.tbody), "une valeur coupée", 400, 200);
  const cPlat = cellule(ligne(plat.tbody), "une valeur qui défile", 400, 200);
  hote.appendChild(normal.hote); hote.appendChild(plat.hote);
  const parHote = marquerLesCellulesTronquees(hote);
  exiger(parHote === 1 && cNormal.classList.contains("plcut") && !cPlat.classList.contains("plcut"),
    `(41h) depuis l'HÔTE d'une liste — le chemin qui couvre les tableaux construits hors de la fabrique — ${parHote} cellule(s) équipées au lieu d'une : les exclusions ne sont pas dérivées sur ce chemin-là`);

  console.log(`[cellule-coupee] le dépli par cellule est EXERCÉ, sur des largeurs que ce témoin POSE lui-même : 3 cellules sur 7 reçoivent le recours (valeur entière au survol, bouton qui DIT son état, chevron), et les quatre autres ne le reçoivent pas — une valeur qui tient, deux cellules qui portent un contrôle (dont un IMBRIQUÉ), une ligne de détail —, la valeur est emboîtée sans perdre un nœud et le bouton reste dernier, le clic déplie sur place et s'arrête AVANT la ligne pendant que le clic de la cellule y va toujours, la re-mesure lit la BOÎTE (la cellule, elle, ne déborde plus) donc le recours ne disparaît pas au premier survol, et quand la valeur tient de nouveau le geste se retire ENTIÈREMENT — nœuds à leur rang, infobulle de la fabrique reprise, infobulle de la VUE laissée. Ce que ce témoin NE tient PAS : rien de l'encre peinte, rien d'une largeur réelle, rien de ce que la feuille impose — il juge ce que le code fait d'une mesure, jamais le résultat à l'écran.`);
}

// ---------------------------------------------------------------------------------------------
// 42. LA FEUILLE DIT CE QU'ELLE FAIT, ET RIEN DE PLUS (`P11.15-b`, `P11.15-c`, `P11.15-d`).
//     POURQUOI UN TÉMOIN DE DÉCLARATION, ET NON DE RENDU. Le simulacre n'a pas de style calculé
//     (section 0) : un masquage, une troncature, une couleur ou une marge imposés par la feuille y sont
//     INVISIBLES. Les trois correctifs jugés ici sont pourtant des DÉCLARATIONS — un jeu de jetons, une
//     marge, l'absence d'un aplat — et une déclaration se lit. Ce témoin lit donc `web/style.css` comme
//     du TEXTE et juge ce qui y est écrit. IL NE DIT RIEN de l'encre réellement peinte : deux règles
//     dont l'une l'emporte sur l'autre lui paraissent également vraies, et la preuve du RENDU passe par
//     un vrai moteur. C'est écrit ici parce que c'est la limite de tout ce qui suit.
//
//     LA PROPRIÉTÉ EST DÉRIVÉE, JAMAIS ÉNUMÉRÉE. Aucune liste de sélecteurs : la classe des règles
//     jugées est calculée sur la feuille entière (les règles qui marquent un état CHOISI, celles qui
//     visent une CELLULE de tableau), et chaque prédicat est validé sur du texte FABRIQUÉ, dans les deux
//     sens, avant de servir. Une règle posée demain tombe donc dessus sans qu'on y pense.
//
//     CE QUE LE PRÉDICAT DE « CHOISI » NE COUVRE PAS, ET POURQUOI C'EST MESURÉ. Il est ancré sur le
//     vocabulaire d'une BASCULE — `.on`, `aria-pressed="true"`, `aria-expanded="true"`. Une règle
//     générale sur toute classe d'état repeindrait le texte des lignes de cas et l'étoile des favoris,
//     qui sont des boutons : c'est le piège `P11.4-m`. Reste une famille voisine, la ligne mise en avant
//     d'une liste de complétion (`.active`) : elle n'est pas dans la classe, et le témoin ne la laisse
//     pas pour autant sans verdict — il exige que son aplat soit celui du SURVOL, écrit dans la MÊME
//     règle. Une mise en avant qui se marquerait par un aplat sans être un survol serait un état choisi
//     sous un autre nom, et elle rougirait ici.
// ---------------------------------------------------------------------------------------------
{
  const feuille = readFileSync(path.join(WEB, "style.css"), "utf8");
  const sansCommentaires = (t) => t.replace(/\/\*[\s\S]*?\*\//g, " ");
  const reglesDe = (t) => [...sansCommentaires(t).matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1].trim().replace(/\s+/g, " "), corps: m[2].trim() }));
  // Un découpage qui RESPECTE LES PARENTHÈSES : `:is(a td, b)` est UNE branche, pas deux. Sans lui, la
  // dernière étape d'un sélecteur fonctionnel se lirait de travers et la classe dérivée serait fausse.
  const decouper = (texte, seps) => {
    const out = []; let prof = 0, cur = "";
    for (const ch of String(texte)) {
      if (ch === "(") prof++; else if (ch === ")") prof--;
      if (prof === 0 && seps.includes(ch)) { if (cur.trim()) out.push(cur.trim()); cur = ""; } else cur += ch;
    }
    if (cur.trim()) out.push(cur.trim());
    return out;
  };
  const branches = (sel) => decouper(sel, ",");
  const derniereEtape = (branche) => { const c = decouper(branche, " >+~"); return c[c.length - 1] || ""; };
  const valeurDe = (corps, prop) => ((corps.match(new RegExp(`(?:^|;)\\s*${prop}\\s*:\\s*([^;]+)`)) || [])[1] || "").trim();
  const declarations = (jeton) => (sansCommentaires(feuille).match(new RegExp("(^|[;{\\s])" + jeton + "\\s*:", "g")) || []).length;

  const REGLES = reglesDe(feuille);

  // (42a) L'INSTRUMENT, AVANT TOUT VERDICT : le lecteur voit la feuille, et il ne voit pas ce qui n'y est pas.
  exiger(REGLES.length > 500, `(42a) instrument : ${REGLES.length} règle(s) lues dans web/style.css — la feuille n'est pas lue, et tout ce qui suit jugerait du vide`);
  exiger(declarations("--sel-bg") === 1 && declarations("--acc") > 0, "(42a) instrument : le compteur de déclarations ne trouve pas des jetons qui SONT dans la feuille");
  exiger(declarations("--jeton-qui-n-existe-nulle-part") === 0, "(42a) instrument : le compteur de déclarations trouve un jeton INEXISTANT — un compte de sa part ne mesurerait rien");
  exiger(branches(":is(.a td,.b>.c)>:is(.d,.e)").length === 1 && branches(".a,.b").length === 2, "(42a) instrument : le découpage des branches ne respecte pas les parenthèses — la classe dérivée plus bas serait fausse");
  exiger(derniereEtape(".qtable td.plcut") === "td.plcut" && derniereEtape(":is(.qtable td,.kv>span)>:is(.badge,.muted)") === ":is(.badge,.muted)", "(42a) instrument : la lecture de la DERNIÈRE étape d'un sélecteur est fausse");

  // (42b) `P11.15-c` — LA MARQUE DU CHOIX N'EST NI UN APLAT NI UNE GRAISSE.
  const MARQUE = /(^|[\s>+~])[^\s>+~,]*(?:\.on|\[aria-pressed="true"\]|\[aria-expanded="true"\])(?![\w-])/;
  const marqueUnChoix = (r) => branches(r.sel).some((b) => MARQUE.test(" " + b));
  exiger(reglesDe('.t.on{color:red}').filter(marqueUnChoix).length === 1 && reglesDe('button[aria-pressed="true"]{color:red}').filter(marqueUnChoix).length === 1,
    "(42b) instrument : le prédicat ne reconnaît pas un état choisi FABRIQUÉ — il ne trouverait rien parce qu'il ne cherche rien");
  exiger(reglesDe(".t{background:red}").filter(marqueUnChoix).length === 0 && reglesDe(".online{background:red}").filter(marqueUnChoix).length === 0,
    "(42b) instrument : le prédicat prend pour un état choisi une règle qui n'en marque aucun (« .online » n'est pas « .on ») — il jugerait la feuille entière");
  const choisies = REGLES.filter(marqueUnChoix);
  exiger(choisies.length >= 15, `(42b) instrument : ${choisies.length} règle(s) d'état choisi dérivées de la feuille — la classe s'est vidée, et un verdict sur une classe vide ne dit rien`);
  for (const r of choisies) {
    const fond = valeurDe(r.corps, "background") || valeurDe(r.corps, "background-color");
    exiger(!fond || fond === "var(--sel-bg)",
      `(42b) « ${r.sel} » marque un état choisi par un APLAT littéral (« ${fond} ») : dans une console de sécurité un aplat de couleur entre en concurrence avec les couleurs qui portent la GRAVITÉ`);
    exiger(!valeurDe(r.corps, "font-weight"),
      `(42b) « ${r.sel} » marque un état choisi par la GRAISSE du mot, que le produit réserve à l'alarme et à la valeur remarquable`);
  }
  for (const jeton of ["--sel-bg", "--sel-fg", "--sel-bd", "--sel-ring"]) {
    exiger(declarations(jeton) === 1, `(42b) « ${jeton} » est déclaré ${declarations(jeton)} fois : la marque du choix n'est plus écrite à UN endroit, et le moyen réservé n'est plus vérifiable d'un coup d'œil`);
  }
  exiger(/--sel-bg\s*:\s*transparent/.test(sansCommentaires(feuille)), "(42b) le jeton de fond de l'état choisi n'est plus transparent : l'aplat revient par la porte des jetons, sur les 16 règles d'un coup");
  const lecteursDesJetons = REGLES.filter((r) => /var\(--sel-(bg|fg|bd)\)/.test(r.corps));
  // Une règle d'état choisi n'est PAS tenue de lire les jetons : l'étoile des favoris et l'interrupteur
  // d'une source disent autre chose (un favori, un état vivant) et gardent leur couleur propre. Ce qui
  // leur est interdit, comme aux autres, c'est l'aplat et la graisse — et c'est déjà exigé ci-dessus.
  const sansJeton = choisies.filter((r) => !/var\(--sel-(bg|fg|bd)\)/.test(r.corps));
  const enAvant = REGLES.filter((r) => branches(r.sel).some((b) => /(^|[\s>+~])[^\s>+~,]*\.active(?![\w-])/.test(" " + b)) && !!(valeurDe(r.corps, "background") || valeurDe(r.corps, "background-color")));
  for (const r of enAvant) {
    exiger(/:hover/.test(r.sel),
      `(42b) « ${r.sel} » marque par un APLAT une ligne mise en avant SANS que cette mise en avant soit celle du survol : c'est un état choisi sous un autre nom, et il échappe à la marque partagée`);
  }

  // (42c) `P11.15-d` — LE SOUS-TITRE RESPIRE, ET SON ÉCART EST ÉCRIT UNE SEULE FOIS.
  const sousTitre = REGLES.filter((r) => branches(r.sel).some((b) => b === ".qsub"));
  exiger(sousTitre.length === 1, `(42c) ${sousTitre.length} règle(s) écrivent le sous-titre partagé : son écart doit venir d'UN endroit, sinon une vue finit par l'ajuster pour elle seule`);
  if (sousTitre.length === 1) {
    const marge = valeurDe(sousTitre[0].corps, "margin");
    exiger(marge.length > 0, "(42c) le sous-titre partagé ne déclare aucune marge : il retombe sur celle du navigateur, qui n'est celle de personne");
    exiger(!/-\d/.test(marge), `(42c) le sous-titre remonte contre son titre par une marge NÉGATIVE (« ${marge} ») : c'est la cause mesurée, pas un effet`);
    exiger(!!valeurDe(sousTitre[0].corps, "line-height") && !!valeurDe(sousTitre[0].corps, "word-spacing"),
      `(42c) le sous-titre n'a ni interligne propre ni espacement de mots : la suite de mentions qu'il porte se relit d'un bloc — « ${sousTitre[0].corps} »`);
  }
  const ajustements = REGLES.filter((r) => !sousTitre.includes(r) && /\.qsub(?![\w-])/.test(r.sel) && /margin/.test(r.corps));
  exiger(ajustements.length === 0, `(42c) ${ajustements.length} règle(s) ajustent la marge du sous-titre à côté de la règle partagée (${ajustements.map((r) => r.sel).join(" · ")}) : une vue s'est écrit une exception`);
  const ecartDesMentions = REGLES.filter((r) => !!valeurDe(r.corps, "margin-inline-start") && /\.badge/.test(r.sel) && /:not\(:first-child\)/.test(r.sel));
  exiger(ecartDesMentions.length === 1, `(42c) ${ecartDesMentions.length} règle(s) donnent son écart à une mention qui qualifie une entrée : la règle doit être écrite UNE seule fois, sur les conteneurs partagés`);
  if (ecartDesMentions.length === 1) {
    exiger(/\.plval/.test(ecartDesMentions[0].sel),
      "(42c) la règle d'écart ne traverse pas la boîte de valeur d'une cellule coupée (`P11.18-b`) : la mention perdrait son blanc au moment PRÉCIS où la valeur devient trop longue, c'est-à-dire là où elle est le plus utile");
    exiger(/:not\(:first-child\)/.test(ecartDesMentions[0].sel),
      "(42c) la PREMIÈRE mention est décalée elle aussi : c'est l'entrée, elle n'a rien à qualifier");
  }
  // LE RÉSIDU, COMPTÉ SUR LE SOURCE ET NON DEVINÉ : une marge écrite en style EN LIGNE par un module
  // l'emporte sur la feuille. Le compte est celui des LIGNES de `web/*.js` qui écrivent à la fois une
  // marge en ligne et l'une des deux classes de mention — c'est une lecture de TEXTE, pas un rendu.
  const margesEnLigne = CORPUS_WEB.filter(([f]) => f.endsWith(".js"))
    .flatMap(([f, src]) => src.split("\n").map((l, i) => [f, i + 1, l]))
    .filter(([, , l]) => /margin(?:-left|-inline-start|\s*:)/.test(l) && /(?:cssText|style=)/.test(l) && /(?:badge|muted)/.test(l));

  // (42d) `P11.15-b` — LA DENSITÉ EST UN JEU DE JETONS, ET LE DÉFAUT NE CHANGE RIEN.
  for (const jeton of ["--dens-y", "--dens-x", "--dens-lh"]) {
    exiger(declarations(jeton) === 3, `(42d) « ${jeton} » est déclaré ${declarations(jeton)} fois au lieu de 3 (le défaut et les deux crans) : la densité n'est plus un jeu de jetons écrit à un endroit`);
  }
  const corpsDuDocument = REGLES.find((r) => branches(r.sel).some((b) => b === "body"));
  exiger(!!corpsDuDocument, "(42d) instrument : la règle du corps du document est introuvable, la comparaison des interlignes jugerait du vide");
  const lhCorps = corpsDuDocument ? valeurDe(corpsDuDocument.corps, "line-height") : "";
  const lhDefaut = ((sansCommentaires(feuille).match(/--dens-lh\s*:\s*([^;}]+)/) || [])[1] || "").trim();
  exiger(!!lhCorps && lhCorps === lhDefaut,
    `(42d) le DÉFAUT de densité change la table alors qu'aucune densité n'est demandée : interligne du corps « ${lhCorps} », défaut du jeton « ${lhDefaut} » — un jeu de jetons doit être neutre tant que personne ne choisit`);
  const viseUneCellule = (r) => branches(r.sel).some((b) => /\.qtable/.test(b) && /^(?:td|th)\b/.test(derniereEtape(b)));
  const cellules = REGLES.filter(viseUneCellule);
  exiger(cellules.length >= 5, `(42d) instrument : ${cellules.length} règle(s) visent une cellule de tableau — la classe dérivée s'est vidée`);
  const hauteurDeLigne = cellules.filter((r) => !!valeurDe(r.corps, "padding") || !!valeurDe(r.corps, "line-height"));
  exiger(hauteurDeLigne.length === 1, `(42d) ${hauteurDeLigne.length} règle(s) font la hauteur d'une ligne de tableau (rembourrage ou interligne) : la densité n'a plus un seul point d'application`);
  for (const r of hauteurDeLigne) {
    exiger(/var\(--dens-y\)/.test(r.corps) && /var\(--dens-x\)/.test(r.corps) && /var\(--dens-lh\)/.test(r.corps),
      `(42d) « ${r.sel} » fait la hauteur d'une ligne sans lire les jetons de densité : « ${r.corps} »`);
  }
  for (const r of cellules) {
    exiger(!valeurDe(r.corps, "height") && !valeurDe(r.corps, "max-height"),
      `(42d) « ${r.sel} » fixe la HAUTEUR d'une cellule (« ${r.corps} ») : le dépli de \`P11.15-a\` s'enroule SUR PLACE et fait grandir la ligne — une hauteur figée le casserait, et c'est la recommandation qui a été corrigée sur son mécanisme`);
  }
  const placeReservee = REGLES.find((r) => /td\.plcut(?![\w->])/.test(r.sel) && !!valeurDe(r.corps, "padding-right"));
  exiger(!!placeReservee && /var\(--dens-plmore\)/.test(placeReservee.corps),
    `(42d) la place réservée au bouton de dépli ne suit pas la taille de ce bouton : au cran resserré, le recours de \`P11.15-a\` serait rogné au moment précis où la table est la plus dense — « ${placeReservee && placeReservee.corps} »`);
  const boutonDeDepli = REGLES.find((r) => branches(r.sel).some((b) => b === ".plmore"));
  exiger(!!boutonDeDepli && valeurDe(boutonDeDepli.corps, "width") === "var(--dens-plmore)" && valeurDe(boutonDeDepli.corps, "height") === "var(--dens-plmore)"
    && /var\(--dens-y\)/.test(valeurDe(boutonDeDepli.corps, "top")) && /var\(--dens-y\)/.test(valeurDe(boutonDeDepli.corps, "right")),
    `(42d) la taille et le retrait du bouton de dépli ne dérivent pas des jetons de densité : « ${boutonDeDepli && boutonDeDepli.corps} »`);
  // LA SURFACE QUI RÈGLE LA DENSITÉ — ARMÉE LE 2026-08-29, ET CE TÉMOIN EST NÉ D'UN AVEU QUI ÉTAIT DEVENU FAUX.
  //
  // CE QUI ÉTAIT ÉCRIT ICI, ET POURQUOI C'ÉTAIT UN DÉFAUT. Ce bloc COMPTAIT les poseurs de `data-density`
  // et imprimait « le mécanisme est posé, pas armé », sans rien EXIGER — au motif que le geste manquant
  // vivait hors de la feuille. Le raisonnement se tenait tant que le compte valait zéro. Le jour où la
  // densité a été armée, le compte est passé de 0 à 1 et CE BANC EST RESTÉ VERT en imprimant une phrase
  // devenue FAUSSE, à chaque exécution. C'est le défaut de `P11.8-h` — un correctif que rien ne tient —
  // dans sa forme la plus retorse : ce n'est pas qu'aucun témoin n'existait, c'est qu'il y en avait un
  // qui REGARDAIT et ne CONCLUAIT PAS. Un compte imprimé n'est pas une garde.
  //
  // QUATRE PROPRIÉTÉS, TOUTES DÉRIVÉES — aucune liste de crans n'est écrite ici, et c'est le point : le
  // jour où la feuille gagne un cran, la parité (53b) rougit tant que le contrôle ne l'offre pas.
  const poseursDeDensite = CORPUS_WEB.filter(([f]) => !f.endsWith(".css")).filter(([, src]) => /data-density|dataset\.density/.test(src)).map(([f]) => f);
  exiger(poseursDeDensite.length >= 1,
    `(53a) plus AUCUNE surface de web/ ne pose « data-density » : la densité est redevenue RÉGLABLE ET NON RÉGLÉE, le mécanisme est posé et désarmé`);

  // (53b) PARITÉ FEUILLE ↔ CONTRÔLE. Les crans que la feuille SAIT rendre, et les valeurs que le contrôle
  // OFFRE, sont dérivés chacun de leur source et comparés. La position « défaut » n'est pas un cran : elle
  // est l'ABSENCE d'attribut, donc la chaîne vide est retirée avant comparaison.
  const srcAppPourDensite = (CORPUS_WEB.find(([f]) => f === "app.js") || [, ""])[1];
  const srcFeuille = (CORPUS_WEB.find(([f]) => f === "style.css") || [, ""])[1];
  const cransDeLaFeuille = [...new Set([...srcFeuille.matchAll(/\[data-density=["']([^"']+)["']\]/g)].map((m) => m[1]))].sort();
  // Les crans OFFERTS sont dérivés de la table du contrôle, bornée à sa déclaration — jamais d'une liste
  // écrite ici. La position par défaut y porte une valeur VIDE (l'absence d'attribut) : elle est retirée,
  // parce que la feuille ne peut pas déclarer un sélecteur pour l'absence d'un attribut.
  const tableDuControle = (srcAppPourDensite.match(/const CRANS = \[[\s\S]*?\n  \];/) || [""])[0];
  const cransDuControle = [...new Set([...tableDuControle.matchAll(/\bv:\s*'([^']*)'/g)].map((m) => m[1]).filter(Boolean))].sort();
  exiger(cransDeLaFeuille.length > 0 && cransDuControle.length > 0,
    `(53b-instrument) un des deux ensembles de crans est VIDE — la parité ne mesure plus rien : feuille=[${cransDeLaFeuille}] contrôle=[${cransDuControle}]`);
  exiger(cransDeLaFeuille.join(",") === cransDuControle.join(","),
    `(53b) la feuille et le contrôle ne s'accordent pas sur les crans de densité : la feuille rend [${cransDeLaFeuille}], le contrôle offre [${cransDuControle}] — un cran que la feuille sait rendre et que personne ne peut choisir est aussi mort qu'un cran choisi que la feuille ignore`);

  // (53c) L'ORDRE, ET C'EST LA SEULE PROPRIÉTÉ QUI TIENNE « AVANT LA PREMIÈRE PEINTURE ».
  // Le jumeau (`initTheme`) ne garantit sa pré-peinture QUE parce que tout le corps de `app.js` tient dans
  // une seule tâche synchrone — mesuré le 2026-08-29 : `route()` est appelé AVANT lui, et c'est `route()`
  // qui pose `.app-ready`, donc qui LÈVE le masquage de `<main>`. Un `await` de premier niveau ajouté
  // demain rendrait cette garantie fausse EN SILENCE. La densité, elle, est posée AVANT `route()` : la
  // propriété ne dépend alors plus d'un raisonnement sur l'ordonnancement, seulement de l'ordre du source.
  // LES DEUX ANCRES SONT DES GESTES, PAS DES MOTS. Une première version de ce témoin cherchait
  // « route() » n'importe où : elle a trouvé un COMMENTAIRE de la l. 191 et déclaré l'ordre inversé alors
  // qu'il est juste. L'appel d'amorçage est le seul en colonne 1 ; la pose est un appel de méthode sur la
  // racine du document. Chaque ancre est exigée UNIQUE : deux occurrences voudraient dire que l'ancre a
  // cessé de désigner un geste, et le témoin mesurerait alors la mauvaise.
  const posesTrouvees = [...srcAppPourDensite.matchAll(/document\.documentElement\.(?:set|remove)Attribute\('data-density'/g)];
  const routesTrouvees = [...srcAppPourDensite.matchAll(/^route\(\);/gm)];
  exiger(posesTrouvees.length === 2 && routesTrouvees.length === 1,
    `(53c-instrument) les ancres ne désignent plus un geste unique : ${posesTrouvees.length} pose(s) de l'attribut (attendu 2 : poser et retirer), ${routesTrouvees.length} appel(s) d'amorçage en colonne 1 (attendu 1) — ce témoin ne mesure plus l'ordre`);
  const posePos = posesTrouvees.length ? posesTrouvees[0].index : -1;
  const routePos = routesTrouvees.length ? routesTrouvees[0].index : -1;
  exiger(posePos < routePos,
    `(53c) la densité est posée APRÈS l'appel qui révèle la vue (pose à ${posePos}, route() à ${routePos}) : l'exploitant verra la page se réagencer sous ses yeux à chaque chargement`);

  console.log(`[feuille] la feuille est lue comme du TEXTE, et trois propriétés en sont DÉRIVÉES. Choisi : ${choisies.length} règle(s) marquent un état choisi (bascule) et AUCUNE n'emploie un aplat littéral ni la graisse du mot ; ${lecteursDesJetons.length} lisent les trois jetons partagés, déclarés une fois chacun, dont le fond vaut « transparent » ; ${sansJeton.length} gardent leur couleur propre (favori, interrupteur) — ce qui leur est interdit, c'est l'aplat, pas leur encre — et ${enAvant.length} règle(s) de mise en avant par aplat sont toutes celles du SURVOL. Sous-titre : une seule règle l'écrit, sa marge est POSITIVE, elle porte interligne et espacement de mots, et une seule règle donne son écart à une mention qui qualifie une entrée — boîte de valeur d'une cellule coupée comprise. Densité : ${cellules.length} règles visent une cellule, UNE SEULE fait la hauteur d'une ligne et lit les trois jetons, aucune ne fixe de hauteur (ce qui casserait le dépli), la place et la taille du bouton dérivent du même jeu, et le défaut vaut l'interligne du corps du document — donc il ne change rien tant que personne ne choisit. CE QUE CE TÉMOIN NE TIENT PAS, ET CE QUE LA FEUILLE N'A PAS : il lit des DÉCLARATIONS, jamais l'encre peinte — la preuve du rendu passe par un vrai moteur ; ${margesEnLigne.length} ligne(s) de web/*.js écrivent une marge en style EN LIGNE sur une mention (${[...new Set(margesEnLigne.map(([f]) => f))].join(", ")}) et l'emportent donc sur la règle unique ; et ${poseursDeDensite.length} surface(s) posent « data-density » — la densité est ARMÉE depuis le 2026-08-29 et ce compte est désormais EXIGÉ, non plus seulement imprimé : (53a) rougit s'il retombe à zéro, (53b) si la feuille et le contrôle cessent de s'accorder sur les crans, (53c) si la pose passe APRÈS l'appel qui révèle la vue. La phrase qui vivait ici disait le mécanisme inerte ; elle est restée VRAIE jusqu'au jour où elle a cessé de l'être, sans que rien ne rougisse — un compte imprimé n'est pas une garde.`);
}

// ---------------------------------------------------------------------------------------------
// 48. UN RÉGLAGE RANGE ET NE RETIRE RIEN ; UNE FIGURE QUI NE DESSINE RIEN EST UN REFUS, PAS UNE
//     ABSENCE (`P11.18-a`, `P11.18-p`, `P11.18-q`). UN SEUL DÉFAUT, DEUX INSTANCES, et les deux ont
//     été INTRODUITES ou LAISSÉES OUVERTES par le lot qui croyait les fermer : un composant qui sait
//     son résultat incomplet et le présente comme complet.
//
//     PREMIÈRE INSTANCE — LE RÉGLAGE RETIRAIT DES COLONNES SERVIES. Mesuré le 2026-08-27 : sur `table`,
//     la seule représentation qui rend TOUTES ses colonnes, un réglage « x=host, y=n » posé sur cinq
//     colonnes servies faisait rendre QUATRE en-têtes là où le MÊME appel sans réglage en rendait SIX.
//     Deux colonnes du démon disparaissaient, l'en-tête et la numérotation des lignes présentaient le
//     reste comme le résultat complet, et AUCUN avis n'était émis — parce que la comparaison de
//     `P11.18-q` ne compare que TROIS positions, et que ce réglage-là ne bougeait aucune des trois.
//     LA CAUSE N'ÉTAIT PAS L'AVEU : `ordreDeFentes` projetait sur au plus trois rangs quel que soit le
//     nombre de colonnes rendues. Le remède ferme le CHEMIN — le sondage répond désormais si la
//     représentation lit AU-DELÀ des trois fentes, et pour celle-là l'ordre est une PERMUTATION
//     COMPLÈTE. Rien à annoncer : il n'y a plus rien de retiré.
//
//     SECONDE INSTANCE — UNE ABSENCE AFFIRMÉE SUR DES LIGNES SERVIES. `pie` et `donut` sur trois lignes
//     dont les valeurs sont toutes nulles — ou négatives — répondaient « aucune donnée ». La colonne EST
//     numérique, donc la porte de DONNÉE laisse passer ; la figure borne à zéro, filtre le strictement
//     positif, se retrouve avec un total nul, et affirme qu'il n'y a rien pendant que TROIS lignes
//     existent. C'est l'instance que `P11.18-p` énumère, restée ouverte pendant que le module la
//     déclarait close. Le remède est une SECONDE porte, qui ne lit pas la donnée mais le RENDU.
//
//     CE QUE CE TÉMOIN TIENT, ET DANS LES DEUX SENS.
//     (a) L'INSTRUMENT : la sonde « lit au-delà des trois fentes » est recalculée ici sur une empreinte
//         INDÉPENDANTE (`outerHTML`, là où le module compare la sienne) et les deux doivent s'accorder
//         mode par mode — avec des modes des DEUX côtés, sans quoi un verdict constant ne dirait rien.
//     (b) LE DÉFAUT, RECONSTITUÉ À LA MAIN : la projection d'AVANT rejouée sur les mêmes entrées perd
//         bien deux colonnes sur cinq. Sans elle, le positif prouverait seulement que quelque chose a
//         changé, pas que le défaut existait.
//     (c) LE POSITIF : le même appel rend TOUTES les colonnes servies, et un réglage qui DÉPLACE les
//         range sans en perdre aucune.
//     (d) L'AVEU NOMME CE QUE LES AUTRES VOIENT, jusqu'à la dernière colonne — et il n'est pas devenu
//         « tout dire » : sur une représentation qui ne lit que deux fentes, il en nomme toujours deux.
//     (e) LA NON-RÉGRESSION EST BYTE-IDENTIQUE : sans réglage, la fabrique réglée rend l'appel d'origine
//         pour les neuf modes sur CINQ colonnes ; et un réglage qui redonne l'ordre par défaut rend le
//         même balisage sans prononcer un mot.
//     (f) LA SECONDE PORTE EST DÉRIVÉE, PAS ÉCRITE PAR TYPE. Le prédicat jugé ici n'emprunte RIEN au
//         vocabulaire des marques du module : une représentation a dessiné quelque chose pour ces
//         lignes si et seulement si son rendu NU diffère de son rendu sur ZÉRO ligne. La porte doit
//         refuser EXACTEMENT les modes qui tracent et dont le rendu ne diffère pas — ni plus, ni moins,
//         sur trois jeux (tout nul, négatif, valide).
//     (g) LE REFUS DIT CE QU'IL A MESURÉ : la colonne, le compte de lignes servies, et la raison
//         DISTINGUÉE — « toutes NULLES » n'est pas « des valeurs NÉGATIVES ».
//     (h) CE QUE LA FIGURE NE MONTRE PAS, ELLE LE DIT : une ligne servie qu'aucun secteur ne porte, et
//         une catégorie dessinée que la légende ne liste pas, sont COMPTÉES et annoncées. Témoin
//         inverse : quand rien n'est perdu, rien n'est ajouté.
//     (i) ZÉRO LIGNE RESTE UNE ABSENCE, et chacune n'en dit que ce qu'elle a mesuré : aucun mode n'est
//         refusé, et `histogram` n'attribue plus à la NATURE de la colonne une absence qu'il n'a pas
//         lue. Témoin inverse : la phrase de la nature EXISTE toujours, sur le seul cas qui l'établit.
//     CE QUE CE TÉMOIN NE TIENT PAS : ni la mise en page ni l'encre peinte (section 0) — un avis rendu
//     est lu sur le TEXTE du document, jamais sur ce qu'un lecteur verrait ; il ne dit rien des panneaux
//     SEMÉS par le démon, dont les requêtes vivent hors de `web/` ; et il ne tient PAS le réglage
//     lui-même : ce qu'il vérifie est qu'un réglage ne RETIRE plus de colonne, pas qu'il HONORE la fente
//     réglée — deux choix d'ordonnée sur cinq étaient encore inertes quand il rendait vert, et c'est le
//     témoin 49 qui l'a fermé. La troncature de la grille de chaleur, nommée ici comme un reste, y est
//     fermée aussi.
// ---------------------------------------------------------------------------------------------
{
  const url48 = (f) => pathToFileURL(path.join(WEB, f)).href;
  const viz48 = await import(url48("viz.js"));
  const prefs48 = await import(url48("prefs.js"));
  const src48 = readFileSync(path.join(WEB, "viz.js"), "utf8");
  // LES MODES SONT LUS DANS LE DISPATCHER, comme au témoin 45 : rien n'est énuméré ici, et un mode posé
  // demain entre dans tout ce qui suit sans qu'on l'écrive.
  const iD = src48.indexOf("function vizSansPorte("), iF = src48.indexOf("function vizElement(");
  exiger(iD >= 0 && iF > iD, "(48-instrument) le dispatcher de représentations n'est plus lisible dans web/viz.js : les modes de ce témoin ne dériveraient de rien");
  const MODES48 = [...new Set([...src48.slice(iD, iF > iD ? iF : iD + 1).matchAll(/mode === '([a-z]+)'/g)].map((m) => m[1]))].concat("table");
  exiger(MODES48.length >= 9, `(48-instrument) ${MODES48.length} mode(s) lus dans le dispatcher, plancher 9 : la lecture est cassée`);

  const cueillir48 = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir48(c, pred, acc)); return acc; };
  const enTetes = (ns) => ns.flatMap((n) => cueillir48(n, (e) => e.tagName === "TH", [])).map((e) => e.textContent);
  const avis48 = (ns) => ns.filter((n) => n.classList && n.classList.contains("rf-hint") && !n.classList.contains("bad"));
  const dernier48 = (ns) => ns[ns.length - 1];

  // ---- (a) L'INSTRUMENT : LA SONDE EST RECALCULÉE SUR UNE EMPREINTE INDÉPENDANTE ----
  // Le module compare `empreinteDe` (balise + attributs + texte) ; ici on compare `outerHTML`. Deux
  // instruments différents qui s'accordent sur les neuf modes, c'est une sonde ; un seul, c'est un aveu.
  const C5 = ["host", "user", "action", "src_ip", "n"];
  const L5 = [[10, 4, 3, 7, 2], [20, 5, 9, 8, 6]];
  const litAuDelaIndependant = (m) => {
    const ref = viz48.vizSansPorte(m, C5, L5, "", "").outerHTML;
    return [2, 3].some((k) => viz48.vizSansPorte(m, C5, L5.map((r) => r.map((v, j) => (j === k ? v + 500 : v))), "", "").outerHTML !== ref);
  };
  const larges = MODES48.filter((m) => viz48.sondage(m).litAuDelaDesFentes);
  const etroites = MODES48.filter((m) => !viz48.sondage(m).litAuDelaDesFentes);
  exiger(larges.length > 0 && etroites.length > 0,
    `(48a-instrument) la sonde ne partage plus les modes (${larges.length} lisent au-delà des trois fentes, ${etroites.length} non) : un verdict constant ne mesurerait rien`);
  for (const m of MODES48) exiger(viz48.sondage(m).litAuDelaDesFentes === litAuDelaIndependant(m),
    `(48a-instrument) « ${m} » : le sondage du module dit « lit au-delà des fentes = ${viz48.sondage(m).litAuDelaDesFentes} » et une empreinte INDÉPENDANTE dit « ${litAuDelaIndependant(m)} » — l'une des deux est aveugle`);

  // ---- (b) LE NÉGATIF : LA PROJECTION D'AVANT, REJOUÉE À LA MAIN, PERD BIEN DEUX COLONNES ----
  const ordreDAvant = (mode, cols, reglage) => {
    const s = viz48.sondage(mode), rang = (nom) => cols.indexOf(nom);
    const ix = reglage.x ? rang(reglage.x) : 0;
    const iy = reglage.y ? rang(reglage.y) : cols.length - 1;
    const is = reglage.s ? rang(reglage.s) : ((s.fentes[1] && cols.length >= 3) ? 1 : -1);
    const o = [ix]; if (is >= 0) o.push(is); o.push(iy); return o;
  };
  const modeLarge = larges[0];
  const perdues = C5.length - ordreDAvant(modeLarge, C5, { x: "host", y: "n" }).length;
  exiger(perdues === 2,
    `(48b-négatif) la projection d'AVANT rejouée sur « ${modeLarge} » ne perd plus deux colonnes sur ${C5.length} (${perdues}) : le positif ci-dessous ne prouverait pas que le défaut existait`);

  // ---- (c) LE POSITIF : LE RÉGLAGE RANGE, IL NE RETIRE RIEN ----
  const R5 = [["w1", "root", "login", "10.0.0.1", 3], ["w2", "adm", "logout", "10.0.0.2", 5]];
  const PANNEAU48 = 4848, CLE48 = "p" + PANNEAU48;
  const rendre48 = (mode, reglage, cols = C5, rows = R5, query = "") => {
    prefs48.prefSet("viz_axes", reglage ? { [CLE48]: reglage } : {});
    return viz48.noeudsDeVizReglee(mode, cols, rows, query, "", PANNEAU48, () => {});
  };
  const sansReglage = enTetes(rendre48(modeLarge, null));
  exiger(sansReglage.length === C5.length + 1 && C5.every((c) => sansReglage.includes(c)),
    `(48c-instrument) sans réglage, « ${modeLarge} » ne rend plus une colonne par colonne servie : ${JSON.stringify(sansReglage)}`);
  const ordreRendu = enTetes(rendre48(modeLarge, { x: "host", y: "n" }));
  exiger(ordreRendu.length === sansReglage.length && C5.every((c) => ordreRendu.includes(c)),
    `(48c) un réglage qui REDONNE l'ordre par défaut retire encore des colonnes SERVIES : ${JSON.stringify(ordreRendu)} au lieu de ${JSON.stringify(sansReglage)}`);
  const deplace = enTetes(rendre48(modeLarge, { x: "action" }));
  exiger(deplace.length === sansReglage.length && C5.every((c) => deplace.includes(c)) && deplace[1] === "action",
    `(48c) un réglage qui DÉPLACE une colonne en perd d'autres, ou ne déplace pas : ${JSON.stringify(deplace)}`);

  // ---- (d) L'AVEU NOMME CE QUE LES AUTRES VOIENT, JUSQU'À LA DERNIÈRE COLONNE ----
  const texteAveu = (mode, reglage) => avis48(rendre48(mode, reglage)).map((n) => n.textContent).join(" ");
  const aveuLarge = texteAveu(modeLarge, { x: "action" });
  exiger(aveuLarge && C5.every((c) => aveuLarge.includes(c)),
    `(48d) l'aveu ne nomme pas les ${C5.length} colonnes que le panneau enregistré remet à « ${modeLarge} » : « ${aveuLarge} »`);
  const modeEtroit = etroites.find((m) => viz48.sondage(m).trace && !viz48.sondage(m).fentes[1]) || etroites[0];
  const aveuEtroit = texteAveu(modeEtroit, { x: "action" });
  exiger(aveuEtroit && !aveuEtroit.includes("src_ip"),
    `(48d-inverse) sur « ${modeEtroit} », qui ne lit pas les colonnes du milieu, l'aveu nomme désormais TOUTES les colonnes : il est devenu « tout dire » et ne suit plus ce que la représentation lit — « ${aveuEtroit} »`);

  // ---- (e) LA NON-RÉGRESSION : SANS RÉGLAGE, ET SUR UN RÉGLAGE QUI NE CHANGE RIEN ----
  for (const m of MODES48) {
    prefs48.prefSet("viz_axes", {});
    const nu48 = dernier48(viz48.noeudsDeVizReglee(m, C5, R5, "q", "", PANNEAU48, () => {}));
    exiger(nu48.outerHTML === viz48.vizElement(m, C5, R5, "q", "").outerHTML,
      `(48e) sans réglage, « ${m} » ne rend plus l'appel \`vizElement\` d'origine sur ${C5.length} colonnes : le chemin par défaut a bougé`);
    const memeOrdre = rendre48(m, { x: C5[0], y: C5[C5.length - 1] }, C5, R5, "q");
    exiger(dernier48(memeOrdre).outerHTML === nu48.outerHTML,
      `(48e) sur « ${m} », un réglage qui REDONNE l'ordre par défaut ne rend plus le même balisage que l'absence de réglage`);
    exiger(avis48(memeOrdre).length === 0,
      `(48e) sur « ${m} », un réglage qui ne change RIEN de ce qui est rendu fait tout de même parler la vue : « ${avis48(memeOrdre).map((n) => n.textContent).join(" ")} »`);
  }
  prefs48.prefSet("viz_axes", {});

  // ---- (f) LA SECONDE PORTE, JUGÉE SUR UN PRÉDICAT QUI N'EMPRUNTE RIEN AU MODULE ----
  // « Cette représentation a-t-elle dessiné quelque chose pour ces lignes ? » est tranché SANS parler de
  // marques : son rendu NU diffère-t-il de son rendu sur ZÉRO ligne ? Si non, elle n'a rien dessiné.
  const C2 = ["bucket", "n"];
  const JEUX = { "tout nul": [[10, 0], [20, 0], [30, 0]], "négatif": [[10, -5], [20, -3]], "valide": [[10, 3], [20, 9], [30, 1]] };
  const neDessineRien = (m, rows) => viz48.vizSansPorte(m, C2, rows, "", "").outerHTML === viz48.vizSansPorte(m, C2, [], "", "").outerHTML;
  const estRefusee = (m, rows) => /Graphe refusé|Chart refused/.test(viz48.vizElement(m, C2, rows, "", "").textContent);
  let muettes = 0;
  for (const [nom, rows] of Object.entries(JEUX)) {
    for (const m of MODES48) {
      const attendu = viz48.sondage(m).trace && neDessineRien(m, rows);
      if (attendu) muettes++;
      exiger(estRefusee(m, rows) === attendu,
        `(48f) sur le jeu « ${nom} », « ${m} » est ${estRefusee(m, rows) ? "REFUSÉE" : "rendue"} alors qu'elle ${attendu ? "ne dessine RIEN (son rendu nu est celui de zéro ligne)" : "dessine, ou ne trace pas"} : la porte de rendu ne suit pas ce qu'elle prétend mesurer`);
    }
  }
  exiger(muettes > 0, "(48f-instrument) aucun mode ne se tait sur aucun des trois jeux : ce témoin ne mesurerait qu'un accord de silences");
  exiger(MODES48.some((m) => !estRefusee(m, JEUX["tout nul"])),
    "(48f-inverse) la porte de rendu refuse TOUS les modes sur un total nul : elle emporte au lieu de trancher");

  // ---- (g) LE REFUS DIT CE QU'IL A MESURÉ, ET DISTINGUE LES DEUX RAISONS ----
  const modeMuet = MODES48.find((m) => viz48.sondage(m).trace && neDessineRien(m, JEUX["tout nul"]));
  exiger(!!modeMuet, "(48g-instrument) aucun mode ne reste muet sur un total nul : les phrases jugées ci-dessous ne seraient rendues par personne");
  const refusNul = viz48.vizElement(modeMuet, C2, JEUX["tout nul"], "", "").textContent;
  const refusNeg = viz48.vizElement(modeMuet, C2, JEUX["négatif"], "", "").textContent;
  exiger(refusNul.includes("n") && /3 ligne/.test(refusNul) && /NULLES/.test(refusNul),
    `(48g) le refus sur un total nul ne nomme pas la colonne, le compte de lignes servies et la raison : « ${refusNul.slice(0, 220)} »`);
  exiger(/NÉGATIVES/.test(refusNeg) && /-5/.test(refusNeg) && !/NULLES/.test(refusNeg),
    `(48g) le refus sur des valeurs négatives rend la phrase du zéro : les deux raisons sont confondues — « ${refusNeg.slice(0, 220)} »`);
  // CE QUI SÉPARE UN REFUS D'UNE ABSENCE N'EST PAS UN MOT — le refus CITE la phrase de l'absence pour dire
  // qu'il ne la rend pas. C'est le NŒUD qui tranche : `noeudDeRefus` porte la classe partagée du refus,
  // là où une absence est rendue par le nœud discret. Jugé sur la forme, donc, pas sur le vocabulaire.
  const noeudNul = viz48.vizElement(modeMuet, C2, JEUX["tout nul"], "", "");
  exiger(noeudNul.classList && noeudNul.classList.contains("rf-hint") && noeudNul.classList.contains("bad"),
    `(48g) ce que rend la porte sur un total nul n'est pas le NŒUD DE REFUS partagé : « ${noeudNul.outerHTML.slice(0, 160)} »`);
  exiger(cueillir48(noeudNul, (n) => n.classList && n.classList.contains("muted"), []).length === 0,
    `(48g) le nœud rendu porte encore la mention discrète d'une absence : « ${noeudNul.outerHTML.slice(0, 160)} »`);
  exiger(/EXISTENT|DO EXIST/.test(refusNul),
    `(48g) le refus ne dit pas que les lignes servies EXISTENT : « ${refusNul.slice(0, 220)} »`);
  // LES DEUX LANGUES, par une seconde instance du module : un refus servi dans une seule langue n'est
  // pas servi. La phrase anglaise doit nommer la même colonne et ne pas garder la française.
  const viz48EN = await import(url48("viz.js") + "?plume-lang=en");
  const refusEN = viz48EN.vizElement(modeMuet, C2, JEUX["tout nul"], "", "").textContent;
  exiger(/Chart refused/.test(refusEN) && refusEN.includes("n") && /ROWS DO EXIST/.test(refusEN) && !/ligne\(s\) servies/.test(refusEN),
    `(48g) sous LANG='en' le refus de figure muette n'est pas rendu en anglais, ou n'y dit plus que les lignes existent : « ${refusEN.slice(0, 220)} »`);
  // NÉGATIF : sans la porte de rendu, la figure affirme toujours l'absence sur des lignes servies.
  const sansPorte = viz48.vizSansPorte(modeMuet, C2, JEUX["tout nul"], "", "").textContent;
  exiger(/aucune donnée|no data/i.test(sansPorte) && JEUX["tout nul"].length === 3,
    `(48g-négatif) « ${modeMuet} » sans la porte n'annonce plus une ABSENCE alors que ${JEUX["tout nul"].length} lignes existent : « ${sansPorte} »`);

  // ---- (h) CE QUE LA FIGURE NE MONTRE PAS, ELLE LE DIT — ET SEULEMENT LÀ ----
  const modeAParts = MODES48.find((m) => viz48.sondage(m).trace && neDessineRien(m, JEUX["tout nul"]));
  const dit = (rows, cols = C2) => cueillir48(viz48.vizElement(modeAParts, cols, rows, "", ""), (n) => n.classList && n.classList.contains("rf-hint"), []).map((n) => n.textContent).join(" ");
  const perdue = dit([[10, -5], [20, 3]]);
  exiger(/1 des 2/.test(perdue) && /négative/.test(perdue),
    `(48h) une ligne servie qu'aucune part ne porte disparaît sans un mot : « ${perdue} »`);
  exiger(dit([[10, 5], [20, 3]]) === "",
    `(48h-inverse) une figure qui ne perd RIEN annonce tout de même une perte : « ${dit([[10, 5], [20, 3]])} » — l'avis suivrait l'existence de la figure et non la perte`);
  const beaucoup = Array.from({ length: 14 }, (_, i) => ["c" + i, i + 1]);
  exiger(/2 catégorie/.test(dit(beaucoup, ["host", "n"])),
    `(48h) la légende s'arrête et ne dit pas combien de catégories dessinées elle ne liste pas : « ${dit(beaucoup, ["host", "n"])} »`);
  exiger(dit(beaucoup.slice(0, 12), ["host", "n"]) === "",
    "(48h-inverse) une légende qui liste TOUT annonce quand même une coupe");

  // ---- (i) ZÉRO LIGNE RESTE UNE ABSENCE, ET CHACUNE N'EN DIT QUE CE QU'ELLE A MESURÉ ----
  for (const m of MODES48) exiger(!estRefusee(m, []),
    `(48i) « ${m} » rend un REFUS sur un résultat SANS AUCUNE ligne : l'absence est un fait, pas un refus`);
  const surZeroLigne = Object.fromEntries(MODES48.map((m) => [m, viz48.vizElement(m, C2, [], "", "").textContent]));
  const fabriquent = MODES48.filter((m) => /numérique|numeric|0\s*\/\s*1/.test(surZeroLigne[m]));
  exiger(fabriquent.length === 0,
    `(48i) sur ZÉRO ligne, ${fabriquent.join(", ")} attribue(nt) encore à la NATURE de la colonne (ou à un rapport) une absence qui n'a rien fait lire : ${JSON.stringify(fabriquent.map((m) => surZeroLigne[m]))}`);
  const disent = MODES48.filter((m) => /aucune donnée|no data/i.test(surZeroLigne[m]));
  exiger(disent.length >= 3,
    `(48i-instrument) seules ${disent.length} représentation(s) DISENT l'absence sur zéro ligne : la mesure du module est fausse`);
  // TÉMOIN INVERSE : la phrase de la NATURE existe toujours — elle a changé de cas, elle n'a pas disparu.
  const natureEncoreLa = viz48.vizSansPorte("histogram", ["h", "v"], [["a", "x"], ["b", "y"]], "", "").textContent;
  exiger(/numérique|numeric/.test(natureEncoreLa),
    `(48i-inverse) la phrase qui nomme la NATURE de la colonne a été SUPPRIMÉE au lieu d'être ramenée à son cas : « ${natureEncoreLa} »`);

  console.log(`[reglage-et-figure-muette] un réglage RANGE et ne retire plus rien : sur « ${modeLarge} », la seule représentation des ${MODES48.length} qui lise au-delà des trois fentes, un réglage rend les ${C5.length} colonnes servies là où la projection d'avant — rejouée ici — en perdait ${perdues}, et l'aveu de réglage privé les NOMME toutes, sans devenir « tout dire » sur celles qui ne lisent que leurs fentes. Le partage entre les deux familles vient d'une sonde à CINQ colonnes, recalculée ici sur une empreinte indépendante et accordée mode par mode. NON-RÉGRESSION : sans réglage, et sous un réglage qui redonne l'ordre par défaut, les ${MODES48.length} modes rendent un balisage byte-identique à l'appel d'origine et ne prononcent pas un mot. Une figure qui ne dessine RIEN sur des lignes servies rend désormais un REFUS qui nomme la colonne, le compte de lignes et la raison — « toutes NULLES » n'étant pas « des valeurs NÉGATIVES » — là où « ${modeMuet} » affirmait « aucune donnée » sur des lignes qui existent ; le prédicat qui le juge n'emprunte rien au vocabulaire des marques du module (le rendu nu est-il celui de zéro ligne ?) et il est vérifié sur trois jeux dans les deux sens, sans emporter les modes qui dessinent. Ce qu'une figure ne montre PAS, elle le compte et le dit — une ligne servie qu'aucune part ne porte, une catégorie dessinée hors légende — et elle se tait quand elle ne perd rien. Sur zéro ligne, aucun mode n'est refusé et aucun n'attribue plus à la NATURE de la colonne une absence qu'il n'a pas lue, la phrase de la nature restant servie sur le seul cas qui l'établit. CE QUE CE TÉMOIN NE TIENT PAS : l'encre peinte et la mise en page (section 0) ; les panneaux SEMÉS par le démon, dont les requêtes vivent hors de web/ ; et le fait qu'un réglage HONORE la fente réglée — il ne juge ici que « rien n'est retiré », et deux choix d'ordonnée sur cinq restaient inertes sous ce vert : c'est le témoin 49 qui le tient, avec la coupe de la grille de chaleur.`);
}

// ---------------------------------------------------------------------------------------------
// 49. LE RÉGLAGE DE L'EXPLOITANT EST HONORÉ, OU L'IMPOSSIBILITÉ EST DITE — ET CE QU'UNE FIGURE
//     LAISSE DE CÔTÉ EST COMPTÉ PAR SA CAUSE LUE (`P11.18-a`, `P11.18-p`, `P11.18-q`).
//
//     LE DÉFAUT, MESURÉ LE 2026-08-27, ET C'ÉTAIT LE PIRE DE SA FAMILLE. Un réglage d'ordonnée posé sur
//     certaines colonnes rendait EXACTEMENT l'ordre SANS réglage : sur cinq colonnes servies, DEUX choix
//     sur cinq étaient inertes ; sur trois colonnes, DEUX sur TROIS ; la 2e dimension portait le même
//     défaut. Le sélecteur continuait pourtant d'afficher le choix, l'infobulle SERVIE affirmait
//     « colonne remise au graphe en dernière position », et l'aveu de réglage privé se taisait puisque
//     rien n'avait bougé. Un réglage qui disparaît sans un mot est pire qu'un réglage refusé : c'est
//     l'exploitant qui croit avoir agi. CAUSE : les rangs de tête étaient RÉSERVÉS avant la boucle, si
//     bien que la pose finale de l'ordonnée ne faisait rien quand sa colonne était déjà placée.
//
//     CE QUE CE TÉMOIN TIENT, ET DANS LES DEUX SENS.
//     (a) L'INSTRUMENT : les FENTES sont lues dans la table du module (leur ORDRE y est la position
//         qu'elles occupent), les MODES dans le dispatcher, et le partage étroit/large dans le sondage.
//         Rien n'est recopié ici, et le contrôle positif exige que sans réglage l'ordre rendu soit
//         l'ordre SERVI — sans quoi « l'ordre a changé » ne voudrait rien dire.
//     (b) LE NÉGATIF, RECONSTITUÉ À LA MAIN : la projection d'AVANT, rejouée sur les mêmes entrées, est
//         INERTE — elle rend l'ordre sans réglage — sur au moins un choix de chaque fente, et elle remet
//         DEUX FOIS la même colonne au graphe sur le chemin étroit. Sans elle, le positif prouverait
//         seulement que quelque chose a changé, pas que le défaut existait.
//     (c) LE POSITIF, BALAYÉ : chaque fente, chaque colonne, sur un résultat à CINQ et à TROIS colonnes.
//         La colonne réglée occupe la position que son infobulle promet, aucune colonne servie n'est
//         perdue, aucune n'est rendue deux fois, et aucun refus ne se glisse là comme une échappatoire.
//     (d) LE CHEMIN ÉTROIT AUSSI : sur une représentation qui ne lit QUE ses trois fentes mais les REND
//         toutes, l'ordonnée réglée est bien celle que portent les cellules, et la colonne remise en
//         première position n'est pas la même — le doublon d'avant est fermé.
//     (e) LES DEUX IMPOSSIBILITÉS SE DISENT au lieu de s'évanouir : deux fentes sur la MÊME colonne, et
//         une fente MÉDIANE sur un résultat sans milieu. Le refus nomme la colonne et les libellés que
//         l'exploitant voit. INVERSE, et c'est la moitié qui empêche de crier au loup : un réglage posé
//         sur une fente que la représentation NE LIT PAS ne refuse rien et ne déplace rien.
//     (f) LA NON-RÉGRESSION EST BYTE-IDENTIQUE : un réglage qui nomme, pour CHAQUE fente offerte, la
//         colonne qui y est déjà rend le même balisage que l'absence de réglage, et ne dit pas un mot.
//     (g) UNE ABSENCE N'EST PAS UN ZÉRO, jusque dans le refus. `Number(null)` et `Number('')` valent 0 et
//         sont FINIS : une ligne SANS valeur entrait dans le compte des zéros MESURÉS et la phrase disait
//         « ses 2 valeur(s) sont toutes NULLES » là où UNE des deux ne portait rien. INVERSE : de vrais
//         zéros disent toujours « toutes NULLES », et de vraies négatives toujours « NÉGATIVES ».
//     (h) CE QU'UNE FIGURE ÉCARTE EST NOMMÉ PAR SA CAUSE LUE, pas par une cause supposée : « nulle ou
//         négative » ne se dit plus d'une valeur ABSENTE ni d'une valeur ILLISIBLE. INVERSE : une vraie
//         négative garde sa phrase, et rien n'est dit quand rien n'est perdu.
//     (i) LA GRILLE DIT SA COUPE ET SES COLLISIONS : 60 lignes, 40 colonnes, et les lignes servies dont
//         une AUTRE écrase la cellule. C'était le reste NOMMÉ du lot précédent ; il est fermé ici.
//         INVERSE : une grille qui ne coupe rien et n'écrase rien ne dit rien.
//     (j) UNE FIGURE QUI NE LIT QU'UNE LIGNE LE DIT — et ce n'est pas un REFUS : le nœud est celui de la
//         perte, pas celui du refus, et il ne nomme aucune colonne. INVERSE : sur une seule ligne servie,
//         rien n'est ajouté.
//     (k) L'HISTOGRAMME PARTAGE SES DEUX SÉMANTIQUES SUR LA FORME DU RÉSULTAT, PAS SUR SON ARITÉ : un
//         agrégat d'UNE ligne rend la valeur SERVIE et non « 1 ». INVERSE : un résultat à UNE colonne
//         reste binné.
//     (l) LA LANGUE DE « aucune donnée » EST SERVIE PAR LE LEXIQUE, ET LA MESURE L'ÉTABLIT. Lu HORS du
//         parcours de traduction, `pie` rend du français là où `gauge` rend de l'anglais ; le parcours
//         appliqué, les DEUX rendent « no data ». Ce témoin tient les deux moitiés, pour qu'on ne
//         « corrige » pas une phrase qui atteint déjà son lecteur en retirant la clé qui l'y porte.
//     CE QUE CE TÉMOIN NE TIENT PAS : ni la mise en page ni l'encre peinte (section 0) — tout y est lu
//     sur le TEXTE du document ; il ne dit rien des panneaux SEMÉS par le démon, dont les requêtes vivent
//     hors de `web/` ; et il ne juge pas ce qu'une chaîne de BLANCS (`' '`) devrait valoir : le module la
//     lit comme un zéro, ce qu'il DÉCLARE, et changer cela changerait sa définition partagée du vide.
// ---------------------------------------------------------------------------------------------
{
  const url49 = (f) => pathToFileURL(path.join(WEB, f)).href;
  const viz49 = await import(url49("viz.js"));
  const prefs49 = await import(url49("prefs.js"));
  const src49 = readFileSync(path.join(WEB, "viz.js"), "utf8");

  // ---- (a) L'INSTRUMENT : FENTES, MODES ET PARTAGE, TOUS LUS AILLEURS QU'ICI ----
  const iT = src49.indexOf("const FENTES_DE_REGLAGE = [");
  const iTF = src49.indexOf("\n];", iT);
  exiger(iT >= 0 && iTF > iT, "(49a-instrument) la table des fentes n'est plus lisible dans web/viz.js : les fentes de ce témoin ne dériveraient de rien");
  const FENTES49 = [...src49.slice(iT, iTF).matchAll(/cle: '([a-z]+)'/g)].map((m) => m[1]);
  exiger(FENTES49.length === 3, `(49a-instrument) ${FENTES49.length} fente(s) lues dans la table du module, attendu 3 : la lecture est cassée`);
  const iD49 = src49.indexOf("function vizSansPorte("), iF49 = src49.indexOf("function vizElement(");
  const MODES49 = [...new Set([...src49.slice(iD49, iF49).matchAll(/mode === '([a-z]+)'/g)].map((m) => m[1]))].concat("table");
  exiger(MODES49.length >= 9, `(49a-instrument) ${MODES49.length} mode(s) lus dans le dispatcher, plancher 9`);
  // La POSITION d'une fente est son rang dans la table : la première est en tête, la dernière en queue,
  // les autres à leur index. C'est ce que les infobulles SERVIES promettent, et c'est ce qui est jugé.
  const positionDe = (j, n) => (j === 0 ? 0 : (j === FENTES49.length - 1 ? n - 1 : j));

  const cueillir49 = (el, pred, acc) => { if (pred(el)) acc.push(el); (el.children || []).forEach((c) => cueillir49(c, pred, acc)); return acc; };
  const parClasse49 = (ns, c) => ns.flatMap((n) => cueillir49(n, (e) => e.classList && e.classList.contains(c), []));
  const refusDe49 = (ns) => parClasse49(ns, "bad").map((n) => n.textContent);
  // L'AVEU DE RÉGLAGE PRIVÉ EST UN NŒUD DE TÊTE, l'aveu de PERTE vit DANS la figure : les deux portent la
  // même classe, et seule leur PLACE les sépare. Les confondre ferait passer une perte de données — qui
  // ne dépend que de la donnée — pour un bavardage du réglage.
  const avis49 = (ns) => ns.filter((n) => n.classList && n.classList.contains("rf-hint") && !n.classList.contains("bad")).map((n) => n.textContent);
  const enTetes49 = (ns) => ns.flatMap((n) => cueillir49(n, (e) => e.tagName === "TH", [])).map((e) => e.textContent).filter((t) => t !== "" && t !== "#");

  const C5 = ["host", "user", "action", "src_ip", "n"];
  const R5 = [["w1", "root", "login", "10.0.0.1", 3], ["w2", "adm", "logout", "10.0.0.2", 5]];
  const C3 = ["host", "user", "n"];
  const R3 = [["w1", "root", 3], ["w2", "adm", 5]];
  const PAN49 = 4949;
  const rendre49 = (mode, reglage, cols, rows) => {
    prefs49.prefSet("viz_axes", reglage ? { ["p" + PAN49]: reglage } : {});
    return viz49.noeudsDeVizReglee(mode, cols, rows, "", "", PAN49, () => {});
  };
  // LA BARRE N'OFFRE QUE CE QUE LA REPRÉSENTATION A DIT LIRE — plus toute fente déjà réglée. Avant, la
  // fente de queue était offerte SANS condition, écrite comme une exception. Les deux comportements ne
  // coïncident que parce que les neuf répondent « je lis le dernier rang » : la mesure est ÉPINGLÉE ici,
  // pour qu'un mode qui ne le lirait pas fasse rougir ce témoin au lieu de perdre un contrôle en silence.
  const sansQueue49 = MODES49.filter((m) => !viz49.sondage(m).fentes[FENTES49.length - 1]);
  exiger(sansQueue49.length === 0,
    `(49a-instrument) ${sansQueue49.join(", ")} ne lit/lisent plus la fente de queue : la barre cesse de l'offrir, et l'aveu de « P11.18-q » nomme « (par défaut) » comme sortie d'un contrôle qui n'existerait plus`);
  const large49 = MODES49.find((m) => viz49.sondage(m).litAuDelaDesFentes);
  exiger(!!large49, "(49a-instrument) aucune représentation ne rend au-delà de ses trois fentes : l'ordre remis au graphe ne serait lisible sur aucun rendu");
  for (const [cols, rows] of [[C5, R5], [C3, R3]]) {
    const sans = enTetes49(rendre49(large49, null, cols, rows));
    exiger(sans.length === cols.length && sans.every((c, i) => c === cols[i]),
      `(49a-instrument) sans réglage, « ${large49} » ne rend plus l'ordre SERVI sur ${cols.length} colonnes (${JSON.stringify(sans)}) : « l'ordre a changé » ne voudrait rien dire`);
  }

  // ---- (b) LE NÉGATIF : LA PROJECTION D'AVANT, REJOUÉE À LA MAIN, EST INERTE ----
  const ordreDAvant49 = (mode, cols, reglage) => {
    const s = viz49.sondage(mode), rang = (nom) => cols.indexOf(nom);
    const ix = reglage.x ? rang(reglage.x) : 0;
    const iy = reglage.y ? rang(reglage.y) : cols.length - 1;
    const is = reglage.s ? rang(reglage.s) : ((s.fentes[1] && cols.length >= 3) ? 1 : -1);
    const ordre = [ix]; if (is >= 0) ordre.push(is); ordre.push(iy);
    if (!s.litAuDelaDesFentes) return ordre;
    const vus = new Set(), plein = [];
    const poser = (i) => { if (i >= 0 && i < cols.length && !vus.has(i)) { vus.add(i); plein.push(i); } };
    poser(ix); poser(is);
    cols.forEach((_, i) => { if (i !== iy) poser(i); });
    poser(iy);
    return plein;
  };
  let inertes49 = 0, total49 = 0;
  for (const [cols] of [[C5], [C3]]) {
    const nu = ordreDAvant49(large49, cols, {}).join(",");
    for (let j = 0; j < FENTES49.length; j++) for (const c of cols) {
      total49++;
      const avant = ordreDAvant49(large49, cols, { [FENTES49[j]]: c });
      if (avant.join(",") === nu && cols[positionDe(j, cols.length)] !== c) inertes49++;
    }
  }
  exiger(inertes49 >= 4,
    `(49b-négatif) la projection d'AVANT n'est plus inerte que sur ${inertes49} des ${total49} réglages rejoués : le positif ci-dessous ne prouverait pas que le défaut existait`);
  // ET SUR LE CHEMIN ÉTROIT, ELLE REMETTAIT DEUX FOIS LA MÊME COLONNE : le doublon est l'autre visage du
  // même défaut — la fente non choisie gardait son rang alors que le choix venait de le prendre.
  const etroitTrois49 = MODES49.find((m) => !viz49.sondage(m).litAuDelaDesFentes && viz49.sondage(m).fentes.every(Boolean));
  exiger(!!etroitTrois49, "(49b-instrument) aucune représentation étroite ne lit ses trois fentes : le doublon d'avant ne serait mesurable nulle part");
  const CN = ["a", "b", "c"], RN = [[1, 2, 3], [4, 5, 6]];
  const avantDoublon = ordreDAvant49(etroitTrois49, CN, { [FENTES49[FENTES49.length - 1]]: CN[0] });
  exiger(new Set(avantDoublon).size < avantDoublon.length,
    `(49b-négatif) la projection d'AVANT ne remet plus deux fois la même colonne sur « ${etroitTrois49} » (${JSON.stringify(avantDoublon)}) : le positif de (d) ne prouverait rien`);

  // ---- (c) LE POSITIF : CHAQUE FENTE, CHAQUE COLONNE, SUR CINQ ET SUR TROIS COLONNES ----
  let honorees49 = 0;
  for (const [cols, rows] of [[C5, R5], [C3, R3]]) {
    for (let j = 0; j < FENTES49.length; j++) for (const c of cols) {
      const ns = rendre49(large49, { [FENTES49[j]]: c }, cols, rows);
      const rendu = enTetes49(ns);
      const p = positionDe(j, cols.length);
      exiger(refusDe49(ns).length === 0,
        `(49c) « ${FENTES49[j]}=${c} » sur ${cols.length} colonnes rend un REFUS là où le réglage est possible : « ${refusDe49(ns).join(" ")} »`);
      exiger(rendu[p] === c,
        `(49c) « ${FENTES49[j]}=${c} » sur ${cols.length} colonnes : la position ${p} porte « ${rendu[p]} » et non la colonne réglée — l'ordre rendu est ${JSON.stringify(rendu)}`);
      exiger(rendu.length === cols.length && new Set(rendu).size === cols.length && cols.every((x) => rendu.includes(x)),
        `(49c) « ${FENTES49[j]}=${c} » perd ou double une colonne servie : ${JSON.stringify(rendu)} au lieu des ${cols.length} de ${JSON.stringify(cols)}`);
      honorees49++;
    }
  }
  exiger(honorees49 === (C5.length + C3.length) * FENTES49.length,
    `(49c-instrument) ${honorees49} réglages balayés au lieu de ${(C5.length + C3.length) * FENTES49.length} : le balayage ne couvre plus toutes les fentes de toutes les colonnes`);

  // ---- (d) LE CHEMIN ÉTROIT : L'ORDONNÉE EST HONORÉE, ET AUCUNE COLONNE N'EST REMISE DEUX FOIS ----
  // La représentation choisie ne lit QUE ses trois fentes et les REND toutes : ses cellules portent la
  // colonne de queue, ses en-têtes de ligne celle de tête. On lit donc sur le RENDU laquelle est où.
  const cellules49 = (n) => cueillir49(n, (e) => e.classList && e.classList.contains("heatcell"), []).map((e) => e.textContent).filter(Boolean);
  const tetesLignes49 = (n) => cueillir49(n, (e) => e.classList && e.classList.contains("heatrow"), []).map((e) => e.textContent);
  const cleY49 = FENTES49[FENTES49.length - 1];
  for (const c of CN) {
    const i = CN.indexOf(c);
    const ns = rendre49(etroitTrois49, { [cleY49]: c }, CN, RN);
    const fig = ns[ns.length - 1];
    const attendues = RN.map((r) => String(r[i]));
    exiger(attendues.every((v) => cellules49(fig).includes(v)),
      `(49d) sur « ${etroitTrois49} », régler l'ordonnée sur « ${c} » ne porte pas ses valeurs ${JSON.stringify(attendues)} dans les cellules : ${JSON.stringify(cellules49(fig))}`);
    exiger(!tetesLignes49(fig).some((t) => attendues.includes(t)),
      `(49d) sur « ${etroitTrois49} », la colonne réglée en ordonnée est AUSSI remise en première position (en-têtes ${JSON.stringify(tetesLignes49(fig))}) : une colonne est remise deux fois`);
  }

  // ---- (e) LES DEUX IMPOSSIBILITÉS SE DISENT, ET SEULEMENT LÀ OÙ ELLES EXISTENT ----
  const cleX49 = FENTES49[0], cleS49 = FENTES49[1];
  const doubleFente = rendre49(large49, { [cleX49]: C5[0], [cleY49]: C5[0] }, C5, R5);
  exiger(refusDe49(doubleFente).length === 1 && refusDe49(doubleFente)[0].includes(C5[0]),
    `(49e) deux fentes réglées sur la MÊME colonne ne rendent pas un refus qui la nomme : « ${refusDe49(doubleFente).join(" ")} »`);
  exiger(cueillir49(doubleFente[0], (e) => e.tagName === "SELECT", []).length >= 2,
    "(49e) le refus d'une collision retire la barre qui seule permet de la défaire : le choix serait sans issue");
  const C2 = ["bucket", "n"], R2 = [["a", 3], ["b", 9]];
  const sansMilieu = rendre49(large49, { [cleS49]: C2[0] }, C2, R2);
  exiger(refusDe49(sansMilieu).length === 1 && /MÉDIANE|MIDDLE/.test(refusDe49(sansMilieu)[0]) && refusDe49(sansMilieu)[0].includes(String(C2.length)),
    `(49e) une fente médiane réglée sur un résultat sans milieu ne rend pas un refus qui le dit : « ${refusDe49(sansMilieu).join(" ")} »`);
  // INVERSE : sur une représentation qui NE LIT PAS cette fente, le même réglage ne refuse rien et ne
  // déplace rien — sans quoi ce refus crierait au loup sur des panneaux qui se lisent aujourd'hui.
  const ignoreS49 = MODES49.find((m) => !viz49.sondage(m).fentes[1]);
  exiger(!!ignoreS49, "(49e-instrument) toutes les représentations lisent la fente médiane : l'inverse ci-dessous ne mesurerait rien");
  const nsIgnore = rendre49(ignoreS49, { [cleS49]: C2[0] }, C2, R2);
  prefs49.prefSet("viz_axes", {});
  exiger(refusDe49(nsIgnore).length === 0 && nsIgnore[nsIgnore.length - 1].outerHTML === viz49.vizElement(ignoreS49, C2, R2, "", "").outerHTML,
    `(49e-inverse) sur « ${ignoreS49} », qui NE LIT PAS la fente médiane, y poser un réglage refuse ou change le rendu : « ${refusDe49(nsIgnore).join(" ")} »`);

  // ---- (f) LA NON-RÉGRESSION : UN RÉGLAGE QUI NOMME CE QUI EST DÉJÀ LÀ NE CHANGE RIEN, ET SE TAIT ----
  for (const m of MODES49) {
    const nu = rendre49(m, null, C5, R5);
    const identite = {};
    for (let j = 0; j < FENTES49.length; j++) if (viz49.sondage(m).fentes[j]) identite[FENTES49[j]] = C5[positionDe(j, C5.length)];
    const memeOrdre = rendre49(m, identite, C5, R5);
    exiger(memeOrdre[memeOrdre.length - 1].outerHTML === nu[nu.length - 1].outerHTML,
      `(49f) sur « ${m} », un réglage qui nomme pour CHAQUE fente la colonne qui y est déjà change le balisage rendu`);
    exiger(avis49(memeOrdre).length === 0,
      `(49f) sur « ${m} », un réglage qui ne change RIEN de ce que la représentation lit fait tout de même parler la vue : « ${avis49(memeOrdre).join(" ")} »`);
  }
  prefs49.prefSet("viz_axes", {});

  // ---- (g) UNE ABSENCE N'EST PAS UN ZÉRO, JUSQUE DANS LE REFUS ----
  const muet49 = MODES49.find((m) => viz49.sondage(m).trace
    && viz49.vizSansPorte(m, C2, [[10, 0], [20, 0]], "", "").outerHTML === viz49.vizSansPorte(m, C2, [], "", "").outerHTML);
  exiger(!!muet49, "(49g-instrument) aucune représentation ne reste muette sur un total nul : les phrases jugées ici ne seraient rendues par personne");
  const refus49 = (rows) => viz49.vizElement(muet49, C2, rows, "", "").textContent;
  for (const vide of [null, ""]) {
    const t = refus49([["a", 0], ["b", vide]]);
    exiger(/1 des 2 ligne\(s\) servies ne portent AUCUNE valeur/.test(t),
      `(49g) avec ${JSON.stringify(vide)} en valeur, le refus ne compte pas l'absence à part : « ${t.slice(0, 260)} »`);
    exiger(!/ses 2 valeur\(s\) sont toutes NULLES/.test(t),
      `(49g) une ligne SANS valeur est encore comptée parmi les zéros MESURÉS : « ${t.slice(0, 260)} »`);
  }
  // INVERSE : de vrais zéros et de vraies négatives gardent leur phrase, et l'absence n'est pas ajoutée.
  const toutNul49 = refus49([["a", 0], ["b", 0]]);
  exiger(/ses 2 valeur\(s\) sont toutes NULLES/.test(toutNul49) && !/AUCUNE valeur/.test(toutNul49),
    `(49g-inverse) de vrais zéros ne disent plus « toutes NULLES », ou parlent d'une absence qui n'existe pas : « ${toutNul49.slice(0, 260)} »`);
  const toutVide49 = viz49.vizSansPorte(muet49, C2, [["a", null], ["b", ""]], "", "");
  exiger(/aucune donnée|no data/i.test(toutVide49.textContent),
    `(49g-instrument) « ${muet49} » sans la porte n'annonce plus une absence sur des lignes qui n'ont AUCUNE valeur : le cinquième état ne serait atteint par rien`);

  // ---- (h) CE QU'UNE FIGURE ÉCARTE EST NOMMÉ PAR SA CAUSE LUE ----
  const dit49 = (rows, cols = C2, sansPorte = false) => parClasse49([sansPorte ? viz49.vizSansPorte(muet49, cols, rows, "", "") : viz49.vizElement(muet49, cols, rows, "", "")], "rf-hint").map((n) => n.textContent).join(" ");
  const absente49 = dit49([[10, 5], [20, null], [30, 7]]);
  exiger(/AUCUNE valeur/.test(absente49) && !/nulle ou négative/.test(absente49),
    `(49h) une ligne SANS valeur est encore écartée comme « nulle ou négative » : « ${absente49} »`);
  const illisible49 = dit49([[10, 5], [20, "n/a"], [30, 7]], C2, true);
  exiger(/n’est PAS un nombre|NOT a number/.test(illisible49),
    `(49h) une valeur ILLISIBLE est encore écartée comme « nulle ou négative » : « ${illisible49} »`);
  exiger(/Graphe refusé|Chart refused/.test(viz49.vizElement(muet49, C2, [[10, 5], [20, "n/a"], [30, 7]], "", "").textContent),
    "(49h-instrument) la porte de donnée ne refuse plus une ordonnée illisible : la borne écrite dans le module (« inatteignable par vizElement ») serait fausse");
  const negative49 = dit49([[10, 5], [20, -3], [30, 7]]);
  exiger(/nulle ou négative/.test(negative49) && !/AUCUNE valeur/.test(negative49),
    `(49h-inverse) une vraie négative a perdu sa phrase, ou s'est vu attribuer une absence : « ${negative49} »`);
  exiger(dit49([[10, 5], [20, 7]]) === "",
    `(49h-inverse) une figure qui ne perd RIEN annonce tout de même une perte : « ${dit49([[10, 5], [20, 7]])} »`);

  // ---- (i) LA GRILLE DIT SA COUPE ET SES COLLISIONS ----
  const grille49 = MODES49.find((m) => cueillir49(viz49.vizSansPorte(m, ["r", "c", "v"], [["a", "x", 1]], "", ""), (e) => e.classList && e.classList.contains("heatcell"), []).length > 0);
  exiger(!!grille49, "(49i-instrument) aucune représentation ne rend de cellules de grille : la coupe jugée ici ne serait celle de personne");
  const ditGrille = (cols, rows) => parClasse49([viz49.vizElement(grille49, cols, rows, "", "")], "rf-hint").map((n) => n.textContent).join(" ");
  const R70 = Array.from({ length: 70 }, (_, i) => ["h" + i, i + 1]);
  const coupeL = ditGrille(["host", "n"], R70);
  const lignesRendues = cueillir49(viz49.vizElement(grille49, ["host", "n"], R70, "", ""), (e) => e.classList && e.classList.contains("heatrow"), []).length;
  exiger(lignesRendues < R70.length, `(49i-instrument) la grille ne coupe plus rien sur ${R70.length} lignes (${lignesRendues} rendues) : la phrase de la coupe n'aurait rien à dire`);
  exiger(new RegExp(String(R70.length - lignesRendues) + " des " + R70.length + " ligne").test(coupeL),
    `(49i) la grille coupe ${R70.length - lignesRendues} ligne(s) et ne le dit pas, ou dit un autre chiffre : « ${coupeL} »`);
  const R50 = Array.from({ length: 50 }, (_, i) => ["r0", "c" + i, i + 1]);
  const coupeC = ditGrille(["r", "c", "n"], R50);
  exiger(/colonne\(s\) de la grille ne sont pas montrées|grid column\(s\) are not shown/.test(coupeC),
    `(49i) la grille coupe ses colonnes et ne le dit pas : « ${coupeC} »`);
  const collision = ditGrille(["host", "n"], [["a", 1], ["a", 2], ["b", 3]]);
  exiger(/1 des 3 ligne\(s\) servies ne sont portées par aucune cellule/.test(collision),
    `(49i) une ligne servie dont une AUTRE écrase la cellule disparaît sans un mot : « ${collision} »`);
  exiger(ditGrille(["host", "n"], [["a", 1], ["b", 2]]) === "",
    `(49i-inverse) une grille qui ne coupe rien et n'écrase rien annonce tout de même une perte : « ${ditGrille(["host", "n"], [["a", 1], ["b", 2]])} »`);

  // ---- (j) UNE FIGURE QUI NE LIT QU'UNE LIGNE LE DIT, SANS ÊTRE UN REFUS ----
  // LE NOM DE LA COLONNE EST DISTINCTIF À DESSEIN : jugé sur « n », le prédicat « la phrase ne nomme pas
  // la colonne » serait vrai de toute phrase française qui porte la lettre n — un instrument qui répond
  // toujours « elle la nomme » ne mesure rien. Mesuré en l'écrivant.
  const CJ = ["bucket", "compte_servi"];
  const CINQ = [["a", 10], ["b", 20], ["c", 30], ["d", 40], ["e", 50]];
  const uneSeule49 = MODES49.filter((m) => {
    const n = viz49.vizElement(m, CJ, CINQ, "", "");
    return cueillir49(n, (e) => e.textContent === "20" || e.textContent === "50", []).length === 0 && !/Graphe refusé/.test(n.textContent);
  });
  exiger(uneSeule49.length >= 2 && uneSeule49.length < MODES49.length,
    `(49j-instrument) ${uneSeule49.length} représentation(s) sur ${MODES49.length} ne rendent qu'une ligne : un verdict constant ne mesurerait rien`);
  for (const m of uneSeule49) {
    const n = viz49.vizElement(m, CJ, CINQ, "", "");
    const perte = parClasse49([n], "rf-hint").map((x) => x.textContent).join(" ");
    exiger(/4 des 5 ligne\(s\) servies ne sont pas lues/.test(perte),
      `(49j) « ${m} » retire 4 lignes servies sur 5 sans un mot : « ${n.textContent.slice(0, 200)} »`);
    exiger(parClasse49([n], "bad").length === 0 && !perte.includes(CJ[1]),
      `(49j) « ${m} » rend sa perte comme un REFUS, ou nomme une colonne là où c'est une LIGNE qui manque : « ${perte} »`);
    exiger(parClasse49([viz49.vizElement(m, CJ, [["a", 10]], "", "")], "rf-hint").length === 0,
      `(49j-inverse) « ${m} » annonce une perte sur UNE seule ligne servie, où il n'y a rien à laisser de côté`);
  }

  // ---- (k) L'HISTOGRAMME PARTAGE SUR LA FORME, PAS SUR L'ARITÉ ----
  const barresDe49 = (m, cols, rows) => cueillir49(viz49.vizElement(m, cols, rows, "", ""), (e) => e.tagName === "RECT", []).map((e) => Number(e.attributes.height));
  const binneur49 = MODES49.find((m) => barresDe49(m, ["v"], [[1], [2], [3], [40]]).length > 1 && barresDe49(m, ["v"], [[1], [2], [3], [40]]).some((h) => h === 0));
  exiger(!!binneur49, "(49k-instrument) aucune représentation ne binne une colonne seule : le partage jugé ici n'existerait pas");
  const uneLigne49 = viz49.vizElement(binneur49, ["host", "n"], [["web-01", 42]], "", "").textContent;
  exiger(uneLigne49.includes("web-01") && uneLigne49.includes("42"),
    `(49k) un agrégat d'UNE ligne est encore binné : « ${binneur49} » rend « ${uneLigne49} » là où la donnée servie dit « web-01 » et « 42 »`);
  const deuxLignes49 = viz49.vizElement(binneur49, ["host", "n"], [["web-01", 42], ["web-02", 7]], "", "").textContent;
  exiger(deuxLignes49.includes("web-01") && deuxLignes49.includes("42"),
    `(49k) le même agrégat à DEUX lignes ne rend plus ses libellés servis : « ${deuxLignes49} »`);
  const seuleColonne49 = viz49.vizElement(binneur49, ["n"], [[42]], "", "").textContent;
  exiger(!seuleColonne49.includes("web-01") && /42/.test(seuleColonne49),
    `(49k-inverse) un résultat à UNE colonne n'est plus binné : « ${seuleColonne49} »`);

  // ---- (l) LA LANGUE DE « aucune donnée » EST SERVIE PAR LE LEXIQUE, ET LA MESURE L'ÉTABLIT ----
  const SUFFIXE49 = "?plume-lang=en";
  localStorage.setItem("soc_lang", "en");
  const vizEN49 = await import(url49("viz.js") + SUFFIXE49);
  const { i18nWalk: walk49 } = await import(url49("i18n.js") + SUFFIXE49);
  localStorage.removeItem("soc_lang");
  const disentVide49 = MODES49.filter((m) => /aucune donnée|no data/i.test(vizEN49.vizElement(m, C2, [], "", "").textContent));
  exiger(disentVide49.length >= 3,
    `(49l-instrument) seules ${disentVide49.length} représentation(s) DISENT l'absence sur zéro ligne : la mesure de la langue ne porterait presque sur rien`);
  const enDurFr49 = disentVide49.filter((m) => /aucune donnée/.test(vizEN49.vizElement(m, C2, [], "", "").textContent));
  exiger(enDurFr49.length > 0,
    "(49l-négatif) plus aucune de ces phrases n'est écrite en français en dur : la moitié qui montre que la mesure d'origine lisait le module HORS du parcours de traduction ne mesure plus rien");
  for (const m of disentVide49) {
    const n = vizEN49.vizElement(m, C2, [], "", "");
    walk49(n);
    exiger(/no data/i.test(n.textContent) && !/aucune donnée/.test(n.textContent),
      `(49l) sous LANG='en', « ${m} » sert encore du français APRÈS le parcours de traduction : « ${n.textContent} » — la clé du lexique manque`);
  }

  console.log(`[reglage-honore-ou-dit] LE RÉGLAGE DE L'EXPLOITANT EST HONORÉ : sur « ${large49} », les ${FENTES49.length} fentes × toutes les colonnes d'un résultat à ${C5.length} et à ${C3.length} colonnes (${honorees49} réglages balayés) posent la colonne réglée à la position que son infobulle promet, sans perdre ni doubler une seule colonne servie — là où la projection d'avant, rejouée ici, restait INERTE sur ${inertes49} de ces ${total49} réglages (elle rendait l'ordre SANS réglage) et remettait deux fois la même colonne sur le chemin étroit. Ce qu'un réglage ne peut PAS faire se DIT au lieu de s'évanouir : deux fentes sur la même colonne, une fente médiane sur un résultat sans milieu — chacune nommée avec la colonne et les libellés que l'exploitant voit, la barre restant au-dessus pour la défaire — et un réglage posé sur une fente que la représentation NE LIT PAS ne refuse rien et ne déplace rien. NON-RÉGRESSION : sur les ${MODES49.length} modes, un réglage qui nomme pour chaque fente la colonne qui y est déjà rend un balisage byte-identique et ne prononce pas un mot. UNE ABSENCE N'EST PAS UN ZÉRO : ni dans le refus d'une figure muette (une ligne sans valeur est comptée À PART, les vrais zéros gardant « toutes NULLES »), ni dans ce qu'une figure écarte (« nulle ou négative » ne se dit plus d'une valeur absente ni d'une valeur illisible). CE QU'UNE FIGURE NE MONTRE PAS, ELLE LE COMPTE : la grille dit sa coupe (${R70.length - lignesRendues} lignes sur ${R70.length}) et les lignes qu'une autre écrase, ${uneSeule49.length} représentations disent les lignes servies qu'elles ne lisent pas — sans que ce soit un refus, et sans nommer une colonne là où c'est une ligne qui manque — et toutes se taisent quand elles ne perdent rien. L'histogramme partage ses deux sémantiques sur la FORME du résultat et non sur son arité. Enfin la langue : « aucune donnée » atteint un lecteur anglophone par le LEXIQUE là où le module l'écrit en dur, mesuré en appliquant le parcours de traduction au nœud rendu — les deux moitiés tenues, pour qu'on ne retire pas la clé qui l'y porte. CE QUE CE TÉMOIN NE TIENT PAS : l'encre peinte et la mise en page (section 0) ; les panneaux SEMÉS par le démon, dont les requêtes vivent hors de web/ ; et ce qu'une chaîne de BLANCS devrait valoir — le module la lit comme un zéro, et il le déclare.`);
}

// ---------------------------------------------------------------------------------------------
// 50. UN PANNEAU DIT À L'ÉCRAN CE QU'IL N'A PAS PU VOIR (`P10.5-i`).
//
//     LE DÉFAUT, ET IL A DEUX MOITIÉS. Le démon publie désormais, sur toute réponse de panneau,
//     l'horizon sous lequel sa fenêtre n'a rien pu voir. Un aveu qu'aucun module de la console ne
//     lit recréerait mot pour mot un défaut déjà consigné dans ce dépôt — « le démon avoue, la
//     console n'écoute pas ». La seconde moitié est pire : `draw()` sort AVANT tout point de pose
//     situé plus bas dès que `rows` est vide, en affichant « aucune donnée sur la fenêtre » — c'est
//     EXACTEMENT le cas fondateur (une courbe vide sur une fenêtre plus ancienne que l'horizon), et
//     la phrase y est FAUSSE : il y a eu des données, elles n'existent plus.
//
//     CE QUI EST TENU ICI, EN DEUX JAMBES. (a) EXÉCUTÉE : les deux fabriques de `viz.js` et celle de
//     `dashboards.js` sont jouées sur le simulacre, dans les DEUX sens — un panneau réellement
//     amputé porte l'aveu, un panneau complet ne dit RIEN (l'anti-fatigue), un horizon non mesuré ne
//     fabrique aucune date. (b) DÉRIVÉE DU SOURCE : la POSITION de la pose. Une fabrique correcte
//     appelée après le retour anticipé ne servirait à rien ; la population des sites est celle des
//     PHRASES que le module affiche quand il n'a rien à montrer, jamais une liste de lignes.
// ---------------------------------------------------------------------------------------------
{
  const url50 = (f) => pathToFileURL(path.join(WEB, f)).href;
  const viz50 = await import(url50("viz.js"));
  const dash50 = await import(url50("dashboards.js"));
  const texte50 = (n) => (n && n.textContent !== undefined ? n.textContent : String(n));

  // --- (a1) LE BADGE : il ne paraît QUE si la fenêtre est réellement passée sous l'horizon. ---
  const AMPUTE = { coverage: { searched_from: 100, horizon_ts: 1_700_000_000, older_outside_window: true, reason: "retention_floor", notice: "réponse INCOMPLÈTE : la fenêtre demandée descend SOUS l'horizon." } };
  const COMPLET = { coverage: { searched_from: 1_700_100_000, horizon_ts: 1_700_000_000, older_outside_window: false, reason: "retention_floor", notice: "la fenêtre demandée tient AU-DESSUS de l'horizon." } };
  const NON_MESURE = { coverage: { searched_from: 100, reason: "horizon_non_mesure", notice: "l'horizon n'a PAS été mesuré." } };
  const REFUS = { coverage: { searched_from: 100, reason: "portee_non_derivable", notice: "on ne sait pas jusqu'où cette réponse a pu voir." } };
  const PLANCHER = { provenance_non_derivee: true, rollup_note: "le compte affiché est un PLANCHER (plafond top-N du pré-agrégé)." };

  const badge50 = viz50.coverageBadge(AMPUTE);
  exiger(!!badge50, "(50a) un panneau dont la fenêtre descend sous l'horizon ne porte AUCUN badge : l'aveu du démon n'atteint pas l'écran");
  exiger(!!badge50 && /qb-approx/.test(badge50.className), `(50a) le badge n'emprunte pas l'habillage existant : « ${badge50 && badge50.className} »`);
  exiger(!!badge50 && texte50(badge50).trim().length > 0, "(50a) le badge est vide");
  exiger(!!badge50 && (badge50.title || "").includes("INCOMPLÈTE"),
    "(50a) l'infobulle du badge ne reprend pas la phrase du démon : le lecteur voit un mot et aucune cause");
  // L'ANTI-FATIGUE, ET C'EST LE TÉMOIN QUI DONNE SA VALEUR AU PRÉCÉDENT : sur une base où rien n'a
  // jamais été purgé, douze panneaux sur douze porteraient le badge et le panneau réellement amputé
  // serait celui qu'on ne verrait plus.
  exiger(viz50.coverageBadge(COMPLET) === null, "(50a-inverse) un panneau COMPLET porte le badge : un aveu permanent rend la cause illisible quand elle est vraie");
  exiger(viz50.coverageBadge(NON_MESURE) === null, "(50a-inverse) un horizon NON MESURÉ produit pourtant un badge : on annoncerait un fait qu'on n'a pas");
  exiger(viz50.coverageBadge({}) === null && viz50.coverageBadge(null) === null, "(50a-inverse) une réponse SANS aveu produit un badge");

  // --- (a2) LES DEUX NŒUDS DE L'HORIZON, ET LA RAISON DE LEUR SÉPARATION. ---
  const noeuds50 = viz50.coverageHorizonNodes(AMPUTE);
  exiger(Array.isArray(noeuds50) && noeuds50.length === 2,
    "(50a2) l'horizon n'est pas rendu en DEUX nœuds : concaténé à sa date, le libellé serait classé « dynamique » et son entrée de lexique naîtrait MORTE");
  exiger(viz50.coverageHorizonNodes(COMPLET) !== null, "(50a2) un horizon MESURÉ doit être disponible même quand rien n'est resté dehors — c'est le corps sans ligne qui décide de le montrer");
  // LE REFUS DU DÉMON EST UN TROISIÈME CAS, ET IL NE DOIT PAS SE LIRE COMME UNE ABSENCE. `portee_non_derivable`
  // (les panneaux `banned_ip`, livrés et semés) et `horizon_non_mesure` (pool indisponible) sortent SANS
  // horizon : rendre `null` laissait « aucune donnée sur la fenêtre » CONCLURE là où le démon écrit
  // « on ne sait pas jusqu'où cette réponse a pu voir ».
  for (const [nom, cas] of [["portee_non_derivable", REFUS], ["horizon_non_mesure", NON_MESURE]]) {
    const n = viz50.coverageHorizonNodes(cas);
    exiger(Array.isArray(n) && n.length === 1,
      `(50a2-refus) « ${nom} » : le refus de conclure du démon ne produit AUCUN nœud — la console conclurait à l'absence à sa place`);
    const t = Array.isArray(n) ? n.map(texte50).join("") : "";
    exiger(!/\d{4}|\d{2}\/\d{2}/.test(t),
      `(50a2-refus) une DATE est fabriquée alors que l'horizon n'a pas été mesuré : « ${t} »`);
  }
  exiger(viz50.coverageHorizonNodes({}) === null && viz50.coverageHorizonNodes(null) === null,
    "(50a2-inverse) une réponse SANS aveu (binaire antérieur, surface non couverte) doit retomber EXACTEMENT sur l'affichage d'avant");

  // --- (a4) LE PLAFOND TOP-N D'UN PANNEAU OPAQUE ATTEINT L'ÉCRAN. Le démon publiait `rollup_note` et
  //     aucun module ne le lisait : onze panneaux livrés affichaient un PLANCHER comme un compte exact. ---
  const plancher50 = viz50.provenanceBadge(PLANCHER);
  exiger(!!plancher50 && texte50(plancher50).trim().length > 0, "(50a4) un compte PLAFONNÉ par le top-N d'un pré-agrégé ne porte aucun badge : il se lit comme un compte exact");
  exiger(!!plancher50 && (plancher50.title || "").includes("PLANCHER"), "(50a4) l'infobulle ne reprend pas la note du démon");
  // L'ANTI-FATIGUE DE CE BADGE-CI : `provenance_non_derivee` est vrai sur TOUT panneau SQL brut (les
  // courbes de métriques comprises, sans aucun plafond) ; seule la NOTE marque un plafond réel.
  exiger(viz50.provenanceBadge({ provenance_non_derivee: true }) === null,
    "(50a4-inverse) une provenance non dérivée SANS plafond mesuré produit un badge : douze panneaux sur douze le porteraient");
  exiger(viz50.provenanceBadge({ served_from: "rollup", approx: true }) === null && viz50.provenanceBadge({}) === null,
    "(50a4-inverse) une provenance DÉRIVÉE produit le badge du non-dit");

  // … et la séparation SERT : sous LANG='en', le parcours de traduction remplace le LIBELLÉ (nœud
  // entier) et laisse la date. Sans cette moitié, on pourrait retirer la clé sans que rien ne rougisse.
  const SUFFIXE50 = "?plume-lang=en-p105i";
  localStorage.setItem("soc_lang", "en");
  const vizEN50 = await import(url50("viz.js") + SUFFIXE50);
  const { i18nWalk: walk50 } = await import(url50("i18n.js") + SUFFIXE50);
  localStorage.removeItem("soc_lang");
  const hote50 = document.createElement("div");
  const nEN50 = vizEN50.coverageHorizonNodes(AMPUTE);
  exiger(Array.isArray(nEN50) && nEN50.length === 2, "(50a2-en) instrument : les deux nœuds ne sont pas rendus sous LANG='en'");
  if (Array.isArray(nEN50)) {
    hote50.append(...nEN50);
    const avant50 = hote50.textContent;
    walk50(hote50);
    exiger(hote50.textContent !== avant50 && !/horizon de conservation/.test(hote50.textContent),
      `(50a2-en) sous LANG='en', le libellé d'horizon reste français APRÈS le parcours de traduction : « ${hote50.textContent} » — la clé du lexique manque, ou le libellé n'est pas un nœud ENTIER`);
  }

  // --- (a3) LE CORPS SANS LIGNE : trois cas, et « aucune donnée » n'est FAUX que dans un seul. ---
  const phrase50 = () => document.createTextNode("aucune donnée sur la fenêtre");
  const sansAveu50 = dash50.corpsSansLigne({}, phrase50());
  exiger(texte50(sansAveu50).trim() === "aucune donnée sur la fenêtre",
    `(50a3) sans aveu, le corps sans ligne doit rester CE QU'IL ÉTAIT : « ${texte50(sansAveu50)} »`);
  const completSansLigne50 = dash50.corpsSansLigne(COMPLET, phrase50());
  exiger(/aucune donnée sur la fenêtre/.test(texte50(completSansLigne50)) && /horizon de conservation/.test(texte50(completSansLigne50)),
    `(50a3) fenêtre AU-DESSUS de l'horizon : la phrase est VRAIE, elle est conservée, et l'horizon la complète — « ${texte50(completSansLigne50)} »`);
  const ampute50 = dash50.corpsSansLigne(AMPUTE, phrase50());
  exiger(!/aucune donnée sur la fenêtre/.test(texte50(ampute50)) && /horizon de conservation/.test(texte50(ampute50)),
    `(50a3) fenêtre SOUS l'horizon : « aucune donnée sur la fenêtre » est FAUX (il y a eu des données) et doit être REMPLACÉ — « ${texte50(ampute50)} »`);
  // LE REFUS DU DÉMON : la phrase reste (elle est littéralement vraie) et le refus la COMPLÈTE, sans quoi
  // l'écran conclut à l'absence là où le démon dit ne pas savoir.
  const refusSansLigne50 = dash50.corpsSansLigne(REFUS, phrase50());
  exiger(/aucune donnée sur la fenêtre/.test(texte50(refusSansLigne50)) && /n'est pas établi/.test(texte50(refusSansLigne50)),
    `(50a3-refus) un refus de conclure se relit comme une absence établie — « ${texte50(refusSansLigne50)} »`);
  // ET LA PHRASE QUI N'AFFIRME PAS UNE ABSENCE N'EST JAMAIS JETÉE. Sur la branche `warming`, le corps est
  // vide parce que RIEN N'A ENCORE ÉTÉ CALCULÉ : remplacer « chargement (mesure en cours) » par l'horizon
  // fait lire une explication d'ABSENCE sur un corps que le démon déclare non calculé.
  const chargement50 = () => document.createTextNode("… chargement (mesure en cours)");
  const enChauffe50 = dash50.corpsSansLigne(AMPUTE, chargement50(), false);
  exiger(/chargement \(mesure en cours\)/.test(texte50(enChauffe50)) && /horizon de conservation/.test(texte50(enChauffe50)),
    `(50a3-chauffe) la phrase d'ÉTAT DU CALCUL a été JETÉE au profit de l'horizon : l'écran explique par la rétention un corps qui n'a jamais été calculé — « ${texte50(enChauffe50)} »`);
  // … et le paramètre n'est pas décoratif : la MÊME phrase déclarée « affirme une absence » disparaît.
  exiger(!/chargement \(mesure en cours\)/.test(texte50(dash50.corpsSansLigne(AMPUTE, chargement50(), true))),
    "(50a3-chauffe-inverse) instrument : le drapeau de la fabrique ne change rien, donc il ne prouve rien");

  // --- (b) LA POSITION DE LA POSE, DÉRIVÉE DU SOURCE. Une fabrique correcte appelée APRÈS le retour
  //     anticipé ne servirait à rien : c'est précisément ce que la première rédaction de ce correctif
  //     faisait, et c'est le cas fondateur qu'elle laissait muet. ---
  const srcDash50 = readFileSync(path.join(WEB, "dashboards.js"), "utf8");
  const corpsDe50 = (nom) => {
    const i = srcDash50.indexOf(nom);
    if (i < 0) return "";
    let o = srcDash50.indexOf("{", i), prof = 0;
    for (let k = o; k < srcDash50.length; k++) {
      if (srcDash50[k] === "{") prof++;
      else if (srcDash50[k] === "}" && --prof === 0) return srcDash50.slice(o, k + 1);
    }
    return "";
  };
  for (const [nom, cond] of [["function draw()", "!result.rows.length"], ["function renderServerPaged()", "!spg.rows.length"]]) {
    const corps = corpsDe50(nom);
    exiger(corps.length > 0, `(50b-instrument) « ${nom} » introuvable dans dashboards.js — la garde ne lit plus rien`);
    const iVide = corps.indexOf(cond);
    const iPose = corps.indexOf("corpsSansLigne(", iVide);
    const iRetour = corps.indexOf("return", iVide);
    exiger(iVide >= 0 && iPose > iVide && iRetour > iVide && iPose < iRetour,
      `(50b) dans « ${nom} », l'aveu n'est pas posé AVANT le retour anticipé sur un résultat sans ligne : l'écran continuerait de dire « aucune donnée » sur une fenêtre passée sous l'horizon`);
  }
  // POPULATION DÉRIVÉE DE LA STRUCTURE, ET C'EST LA MOITIÉ QUI TIENT. Un site qui REMPLACE le corps d'un
  // panneau ou d'une carte SOUS CONDITION D'UN `rows` VIDE doit passer par la fabrique. Le motif porte
  // sur la CONDITION (`!x.rows…`) et sur le GESTE DE RENDU (`replaceChildren`/`appendChild`) — jamais sur
  // la phrase affichée : un cinquième site écrit demain avec une formulation neuve (« aucun résultat sur
  // cette fenêtre ») y entre le jour même. Les deux sites qui testent `rows` SANS rendre — le garde-fou
  // de l'export et le « pas encore chargé » de la pagination serveur — en sortent par une PROPRIÉTÉ (ils
  // ne rendent rien), pas par une exception inscrite quelque part.
  const RE_ROWS_VIDE = /!\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.rows\b/g;
  const sitesVides50 = [];
  const lignesDash50 = srcDash50.split("\n");
  const vus50 = new Set();
  for (const m of srcDash50.matchAll(RE_ROWS_VIDE)) {
    const ligne = srcDash50.slice(0, m.index).split("\n").length;
    if (vus50.has(ligne)) continue;
    vus50.add(ligne);
    const brut = (lignesDash50[ligne - 1] || "").trim();
    if (brut.startsWith("//") || brut.startsWith("*")) continue;
    const fenetre = srcDash50.slice(m.index, m.index + 300);
    const iRendu = fenetre.search(/replaceChildren\(|appendChild\(/);
    if (iRendu < 0) continue;   // teste `rows` sans RENDRE : hors population
    // Le site RAPPORTÉ est celui du GESTE DE RENDU, pas celui de la condition : c'est la ligne qu'il faut
    // ouvrir quand la garde rougit.
    const ligneRendu = srcDash50.slice(0, m.index + iRendu).split("\n").length;
    sitesVides50.push([ligneRendu, (lignesDash50[ligneRendu - 1] || "").trim().slice(0, 90), fenetre.includes("corpsSansLigne(")]);
  }
  exiger(sitesVides50.length >= 3,
    `(50b-instrument) ${sitesVides50.length} site(s) de rendu sur corps vide dérivés de dashboards.js, plancher 3 — la dérivation est cassée et la garde mesurerait le vide`);
  const horsFabrique50 = sitesVides50.filter(([, , ok]) => !ok);
  exiger(horsFabrique50.length === 0,
    `(50b) ces corps sans ligne ne passent pas par la fabrique et se relisent donc comme une absence établie : ${JSON.stringify(horsFabrique50)}`);
  // SECOND FILET, ET IL FAUT DIRE CE QU'IL EST : une recherche des DEUX phrases écrites AUJOURD'HUI. Il
  // attrape la REFORMULATION d'un site existant (la phrase change de place sans passer par la fabrique) ;
  // il n'attrape PAS l'ajout d'un site formulé autrement — c'est le filet structurel ci-dessus qui le
  // fait. Les deux ensembles ne se recouvrent pas : la branche `warming` est conditionnée par `warming`,
  // pas par `rows`, donc elle n'existe que dans celui-ci.
  const phrasesVides50 = lignesDash50
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => /aucune donnée|chargement \(mesure en cours\)/.test(l) && !l.trim().startsWith("//"));
  exiger(phrasesVides50.length >= 4,
    `(50b-instrument) ${phrasesVides50.length} phrase(s) de corps vide trouvées dans dashboards.js, plancher 4 — la dérivation est cassée`);
  const phrasesHorsFabrique50 = phrasesVides50.filter(([, l]) => !l.includes("corpsSansLigne("));
  exiger(phrasesHorsFabrique50.length === 0,
    `(50b) ces phrases de corps vide ne passent pas par la fabrique : ${JSON.stringify(phrasesHorsFabrique50)}`);
  // … et les aveux sont posés sur CHACUN des chemins qui remplacent le corps d'un panneau ou d'une carte.
  const poses50 = (srcDash50.match(/poserLesAveuxDuPanneau\(/g) || []).length - 1; // -1 : la définition
  exiger(poses50 >= 6,
    `(50b) ${poses50} point(s) de pose des aveux, attendu au moins SIX (corps vide de draw, table, graphe, liste paginée pleine ET vide, chauffe, carte d'instantané) — un chemin de rendu sans aveu est un chemin muet`);
  // LES DEUX BRANCHES JUMELLES DE LA LISTE PAGINÉE DISENT LA MÊME CHOSE. `draw()` posait la phrase ET les
  // badges sur son corps vide ; `renderServerPaged()` ne posait que la phrase — deux chemins d'un même
  // écran qui n'avouent pas pareil, ce qu'aucun compteur d'occurrences ne peut voir.
  {
    const corps = corpsDe50("function renderServerPaged()");
    const iVide = corps.indexOf("!spg.rows.length");
    const iRetour = corps.indexOf("return", iVide);
    exiger(iVide >= 0 && corps.slice(iVide, iRetour).includes("poserLesAveuxDuPanneau("),
      "(50b-jumelle) la branche « corps vide » de renderServerPaged ne pose pas les badges, alors que sa jumelle de draw() les pose");
  }

  // --- (c) LA BORNE : LA SURFACE QU'UNE LISTE DE LIGNES INTERROGE, MESURÉE PLUTÔT QU'AFFIRMÉE. ---
  // Un panneau `table` non agrégé (`serverPaged()`) NE PASSE PAS par la route de panneau : `load()` sort
  // sur `loadServerPage`, qui interroge `/api/query` — surface qui ne publie AUCUN `stats.coverage`. Les
  // poses de `renderServerPaged` sont donc, sur l'arbre d'aujourd'hui, INERTES EN PRODUCTION : elles
  // rendent `null` et la phrase d'avant est conservée. Ce n'est pas une régression (c'est l'écran
  // d'avant le lot), c'est un RESTE — et il est mesuré ici pour qu'on ne puisse pas le croire clos.
  const corpsPage50 = corpsDe50("async function loadServerPage(");
  exiger(corpsPage50.length > 0, "(50c-instrument) « loadServerPage » introuvable — la borne ne lit plus rien");
  const surfacePage50 = ((corpsPage50.match(/fetch\('([^']+)'/) || [])[1] || "");
  exiger(surfacePage50 === "/api/query",
    `(50c-borne) la liste de lignes d'un panneau interroge « ${surfacePage50} » et non « /api/query » : si c'est désormais la route de panneau (ou si /api/query publie un aveu), les poses de renderServerPaged cessent d'être inertes — refermez le reste et retirez cette borne.`);

  console.log(`[panneau-avoue] UN PANNEAU DIT À L'ÉCRAN CE QU'IL N'A PAS PU VOIR : le badge paraît quand la fenêtre est réellement passée sous l'horizon et SE TAIT autrement (fenêtre au-dessus, réponse sans aveu) ; le REFUS de conclure du démon (portée non dérivable, horizon non mesuré) rend un nœud qui DIT ce refus et aucune date, au lieu de laisser « aucune donnée sur la fenêtre » conclure à sa place ; le plafond top-N d'un panneau opaque atteint enfin l'écran, et seulement là où une note le chiffre ; l'horizon est rendu en DEUX nœuds, ce qui laisse le parcours de traduction remplacer le libellé sans toucher à la date — mesuré sous LANG='en' ; « aucune donnée sur la fenêtre » est CONSERVÉ quand il est vrai et REMPLACÉ quand il est faux, tandis que « chargement (mesure en cours) », qui décrit un ÉTAT DU CALCUL et non une absence, n'est JAMAIS jeté ; la POSITION de la pose est dérivée du source (dans draw() comme dans renderServerPaged(), l'aveu précède le retour anticipé) et la population des corps vides est dérivée de la STRUCTURE (condition sur \`rows\` + geste de rendu), pas de l'orthographe des phrases. CE QUE CE TÉMOIN NE TIENT PAS : il ne rend aucun panneau de bout en bout (la fabrique de carte n'est pas exportée), donc il ne prouve pas que \`result.stats\` arrive intact jusqu'à draw() ; et il MESURE le reste au lieu de le taire — une liste de lignes serveur-paginée interroge \`/api/query\`, surface sans aveu, donc les poses de renderServerPaged y sont inertes tant que ce reste n'est pas fermé.`);
}

// ---------------------------------------------------------------------------------------------
// 51. UN REFUS DE LIRE N'EST NI UNE ABSENCE NI UNE PANNE — SUR LES DEUX VUES OÙ IL SE PRÉSENTAIT
//     COMME L'UNE OU L'AUTRE (`P10.7-d`, tenu par `P11.8-h`).
//
//     POURQUOI CE TÉMOIN EXISTE, ET C'EST LE CONSTAT DE `P11.8-h`. Le correctif de `P10.7-d` a été
//     fermé sur une preuve PAR EXERCICE jouée dans un bac à sable jeté avec la session. MESURÉ le
//     2026-08-29 : la sortie de ce banc était BYTE-IDENTIQUE avec le code d'avant et celui d'après —
//     zéro ligne de différence, code de sortie 0 des deux côtés. N'importe qui pouvait défaire le
//     geste sans qu'une garde rougisse.
//
//     LE PIÈGE EST PIRE QU'UNE ABSENCE, ET C'EST LUI QUI EST TENU ICI. Sur l'inventaire de flotte, un
//     refus servi en 200 (`{hosts: [], error: <cause>}`, corps que forme `portillon::corps_de_refus`)
//     ne rendait pas « rien » : la bannière d'alarme se déclenchait, parce qu'elle est conditionnée à
//     `pipeline_fresh`, ABSENT d'un corps de refus. La console AFFIRMAIT donc un incident de collecte
//     sur une chaîne qui va bien. Un témoin qui se contenterait de vérifier que le mot « refus »
//     apparaît laisserait revenir exactement cette panne inventée : il faut TROIS issues distinctes
//     sur la MÊME vue.
//
//     RIEN N'EST RECOPIÉ, ET C'EST DÉLIBÉRÉ (le piège a déjà été payé deux fois dans ce fichier). La
//     phrase d'alarme et la phrase de vide ne sont pas écrites ici : elles sont DÉRIVÉES du rendu des
//     deux charges qui les produisent, puis cherchées dans le rendu du refus. Une reformulation ne
//     casse donc pas ce témoin, mais un aplatissement des trois issues sur une seule, si. La cause
//     injectée est visiblement FABRIQUÉE : citer le démon la ferait vieillir en silence.
// ---------------------------------------------------------------------------------------------
{
  const CAUSE_51 = "CAUSE-DE-REFUS-FABRIQUÉE-PAR-CE-BANC-51 : aucune phrase du démon n'est citée ici";

  // --- (a) L'INVENTAIRE DE FLOTTE : refus, vraie panne, vrai vide, sur la même fonction pure. ---
  const { renderFleetInventory } = await import(pathToFileURL(path.join(WEB, "fleet.js")).href);
  const rendreFlotte = (charge) => { const w = new Element("div"); renderFleetInventory(w, charge); return w; };
  const MAINTENANT_51 = 1800000000;
  const panne51 = rendreFlotte({ hosts: [], pipeline_fresh: false, now: MAINTENANT_51 });
  const vide51 = rendreFlotte({ hosts: [], pipeline_fresh: true, now: MAINTENANT_51 });
  const refus51 = rendreFlotte({ hosts: [], error: CAUSE_51, now: MAINTENANT_51 });
  // L'INSTRUMENT D'ABORD : sans la branche d'alarme RÉELLEMENT atteinte ici, « le refus ne l'atteint
  // pas » ne prouverait rien — ce serait un banc qui ne peut pas rougir.
  const banniere51 = (w) => w.children[0];
  const derniere51 = (w) => w.children[w.children.length - 1];
  exiger(panne51.children.length === 2 && !!banniere51(panne51) && banniere51(panne51).classList.contains("bad"),
    `(51a-instrument) la charge « pipeline non frais » n'atteint pas la branche d'alarme de l'inventaire de flotte (${panne51.children.length} nœud(s), classe « ${banniere51(panne51) ? banniere51(panne51).className : "aucun"} ») : ce témoin ne pourrait pas rougir`);
  exiger(vide51.children.length === 2 && !!banniere51(vide51) && !banniere51(vide51).classList.contains("bad"),
    `(51a-instrument) la charge « pipeline frais, parc vide » alarme quand même (classe « ${banniere51(vide51) ? banniere51(vide51).className : "aucun"} ») : les deux charges de référence ne se distinguent plus`);
  // Le banc ne MEURT pas sur un nœud absent : une exception ici emporterait en silence tous les témoins
  // qui suivent, ce qui est exactement le défaut que `P11.8-h` ferme (mesuré le 2026-08-29 : la première
  // version de ce lot est morte sur un `title` nul et le témoin 53 n'a jamais été joué).
  const texteDe51 = (n) => (n && n.textContent) || "";
  const PHRASE_D_ALARME_51 = texteDe51(banniere51(panne51));
  const PHRASE_DE_VIDE_51 = texteDe51(derniere51(vide51));
  exiger(PHRASE_D_ALARME_51.length > 20 && PHRASE_DE_VIDE_51.length > 20 && PHRASE_D_ALARME_51 !== PHRASE_DE_VIDE_51,
    `(51a-instrument) les deux phrases de référence ne sont pas dérivables (alarme ${PHRASE_D_ALARME_51.length} car., vide ${PHRASE_DE_VIDE_51.length} car.)`);
  exiger(texteDe51(derniere51(panne51)) === PHRASE_DE_VIDE_51,
    "(51a-instrument) la panne et le vrai vide ne partagent plus la même ligne de parc vide : la dérivation ne porte plus sur ce qu'elle croit");
  // ... ET LE REFUS, ALORS, N'EST NI L'UNE NI L'AUTRE.
  exiger(refus51.textContent.includes(CAUSE_51),
    `(51a) un refus de lire l'inventaire de flotte ne rend pas la cause que le démon nomme : « ${refus51.textContent} »`);
  exiger(!refus51.textContent.includes(PHRASE_D_ALARME_51),
    `(51a) UN REFUS DE LIRE EST RENDU COMME UNE PANNE D'INGESTION CONSTATÉE : la vue n'a rien lu et affirme un incident sur la chaîne de collecte — un exploitant qui la croit ouvre une intervention sur une chaîne qui va bien. Rendu du refus : « ${refus51.textContent} »`);
  exiger(!refus51.textContent.includes(PHRASE_DE_VIDE_51),
    `(51a) un refus de lire l'inventaire de flotte est rendu comme un parc vide : rien n'a été lu, donc rien n'établit qu'aucun hôte ne pousse. Rendu du refus : « ${refus51.textContent} »`);
  exiger(refus51.children.length === 1,
    `(51a) le rendu d'un refus porte ${refus51.children.length} nœud(s) au lieu du seul aveu : une ligne d'hôte, une barre d'export ou une bannière posée sur un corps NON LU présente comme un relevé ce qui n'a pas été relevé`);
  exiger(!panne51.textContent.includes(CAUSE_51) && !vide51.textContent.includes(CAUSE_51),
    "(51a-instrument) une charge SANS cause rend quand même la cause : la dérivation lit autre chose que ce qu'elle croit");
  exiger(new Set([refus51.textContent, panne51.textContent, vide51.textContent]).size === 3,
    "(51a) les trois issues de l'inventaire de flotte (refus, panne, vide) ne rendent pas trois textes distincts");

  // --- (b) LA MATRICE DE COUVERTURE ATT&CK : même triplet, sur la vue où « aucune technique
  //         détectée » se lit comme un VERDICT de couverture et non comme un vide. ---
  const { renderCoverage } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const rendreCouverture = async (corps) => {
    const hote = new Element("div");
    const qsOrigine = document.querySelector, fetchOrigine = globalThis.fetch;
    document.querySelector = (sel) => (sel === "#cov-body" ? hote : qsOrigine(sel));
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify(corps) });
    try { await renderCoverage(); } finally { document.querySelector = qsOrigine; globalThis.fetch = fetchOrigine; }
    return hote;
  };
  const refusCov51 = await rendreCouverture({ detections: [], error: CAUSE_51 });
  const videCov51 = await rendreCouverture({ detections: [] });
  const pleinCov51 = await rendreCouverture({ detections: [{ mitre: "T1059", count: 2, first_ts: MAINTENANT_51 }] });
  const PHRASE_D_ABSENCE_51 = videCov51.textContent;
  exiger(PHRASE_D_ABSENCE_51.length > 20 && pleinCov51.textContent.includes("T1059"),
    `(51b-instrument) les charges de référence de la couverture ne rendent pas ce qu'elles doivent (vide ${PHRASE_D_ABSENCE_51.length} car., plein « ${pleinCov51.textContent} ») : ce témoin ne pourrait pas rougir`);
  exiger(refusCov51.textContent.includes(CAUSE_51),
    `(51b) un refus de lire la couverture ATT&CK ne rend pas la cause que le démon nomme : « ${refusCov51.textContent} »`);
  exiger(!refusCov51.textContent.includes(PHRASE_D_ABSENCE_51),
    `(51b) UN REFUS DE LIRE LA COUVERTURE EST RENDU COMME UN VERDICT DE COUVERTURE : sur une matrice purple, cette phrase-là se lit « rien ne nous a touchés » ou « nos règles ne détectent rien », et elle sort d'une lecture qui n'a PAS eu lieu. Rendu du refus : « ${refusCov51.textContent} »`);
  exiger(new Set([refusCov51.textContent, videCov51.textContent, pleinCov51.textContent]).size === 3,
    "(51b) les trois issues de la couverture ATT&CK (refus, vide, détections) ne rendent pas trois textes distincts");
  const badCov51 = refusCov51.children.find((c) => c.classList && c.classList.contains("bad"));
  exiger(!!badCov51, `(51b) le refus de la couverture n'est pas rendu dans le registre d'un aveu (classes : ${refusCov51.children.map((c) => c.className).join(" | ") || "aucun enfant"})`);

  console.log(`[refus-pas-absence] deux vues, trois issues chacune sur la MÊME fonction : l'inventaire de flotte rend un refus (${refus51.children.length} nœud) qui NOMME sa cause sans jamais reprendre ni la phrase d'alarme d'ingestion (${PHRASE_D_ALARME_51.length} car., dérivée de la charge « pipeline non frais ») ni la phrase de parc vide (${PHRASE_DE_VIDE_51.length} car.), et la matrice de couverture ATT&CK rend un refus distinct de son absence (${PHRASE_D_ABSENCE_51.length} car.) comme de ses détections. Aucune phrase n'est écrite ici : les trois sont DÉRIVÉES du rendu, la cause injectée est fabriquée. CE QUE CE TÉMOIN NE TIENT PAS : il juge le TEXTE d'un arbre, pas ce qu'un moteur de rendu en peint — une phrase d'aveu masquée par la feuille de style lui paraîtrait rendue.`);
}

// ---------------------------------------------------------------------------------------------
// 52. UN CONTRÔLE VISIBLE QUI NE PEUT RIEN FAIRE N'EST PAS OFFERT — ET SON RETRAIT SUIT L'ÉCRIVAIN
//     UNIQUE DE LA PLAGE (`P11.20-f`, tenu par `P11.8-h`).
//
//     CE QUE CE TÉMOIN TIENT, ET CE QU'UN TÉMOIN PARESSEUX AURAIT LAISSÉ PASSER. La présence du bouton
//     qui efface les dates est DÉRIVÉE de ce qu'il aurait à retirer — une plage posée, une date
//     saisie, une phrase de refus affichée. Vérifier le seul état d'ARRIVÉE ne suffirait pas : le
//     chemin qu'un correctif mal posé rate est le QUATRIÈME, celui où une AUTRE vue posée sur la même
//     cible retire la plage. Il ne passe pas par un geste de cette barre-ci, mais par l'écrivain
//     unique `poserLaPlageSurLaCible` — et sans reflet depuis LUI, le bouton resterait offert sur un
//     contrôle qui n'a plus rien à retirer, c'est-à-dire exactement le défaut que la clé ferme.
//
//     LE SIMULACRE NE PEINT RIEN, ET CE TÉMOIN NE PRÉTEND PAS AUTRE CHOSE. Il juge `hidden` et
//     `disabled` sur le nœud, pas ce qu'une feuille de style en ferait à l'écran ; c'est d'ailleurs
//     pourquoi la console retire ce bouton au lieu de le griser (aucune règle `:disabled` ne vise sa
//     classe), et cette raison-là se garde ailleurs — le témoin 42 lit la feuille.
//
//     LA CIBLE ET LA PORTE SONT FABRIQUÉES ICI, jamais empruntées à une vue : deux contrôles posés sur
//     LA MÊME cible fabriquée reproduisent « deux vues, une fenêtre » sans toucher au journal d'audit
//     ni au panneau d'accès données, dont les contrôles vivent dans le même registre.
// ---------------------------------------------------------------------------------------------
{
  const { poserLeChoixDeDates, poserLaPlageSurLaCible } = await import(pathToFileURL(path.join(WEB, "core.js")).href);
  let plage52 = null;
  const cible52 = { grain: "jour", lire: () => plage52, poser: (p) => { plage52 = p; } };
  const porte52 = { borneHaute: true, refus: () => "REFUS-FABRIQUÉ-PAR-CE-BANC-52" };
  const PLAGE_52 = { texteDebut: "2026-01-01", texteFin: "2026-01-02", debut: 1767225600, fin: 1767398399 };
  const etat = (c) => `hidden=${c.retirer.hidden} disabled=${c.retirer.disabled}`;

  // (a) À L'ARRIVÉE, RIEN N'EST POSÉ : le bouton n'est pas offert.
  const c52 = poserLeChoixDeDates("temoin-p11-20-f-a", cible52, porte52, () => {});
  const MOTIF_INERTE_52 = c52.retirer.getAttribute("title");
  exiger(c52.retirer.hidden === true && c52.retirer.disabled === true,
    `(52a) à l'ARRIVÉE — aucune plage posée, deux champs vides, aucun refus — le bouton d'effacement est OFFERT alors qu'il n'a rien à retirer : c'est un contrôle visible qui ne peut rien faire, et il est là où l'exploitant le rencontre en premier (${etat(c52)})`);

  // (b) UNE DATE FRAPPÉE : il paraît, et il repart quand la frappe est effacée.
  c52.debut.value = "2026-01-01";
  c52.debut.dispatchEvent({ type: "input" });
  const MOTIF_ACTIF_52 = c52.retirer.getAttribute("title");
  exiger(c52.retirer.hidden === false && c52.retirer.disabled === false,
    `(52b) une date vient d'être saisie et le bouton qui l'effacerait n'est pas offert (${etat(c52)})`);
  c52.debut.value = "";
  c52.debut.dispatchEvent({ type: "input" });
  exiger(c52.retirer.hidden === true,
    `(52b) la date saisie a été effacée et le bouton reste offert : la présence n'est pas DÉRIVÉE de l'état, elle est posée une fois (${etat(c52)})`);

  // (c) UNE PHRASE DE REFUS AFFICHÉE EST AUSSI QUELQUE CHOSE À RETIRER — troisième terme du prédicat,
  //     celui qu'une garde énumérée oublierait.
  c52.direLeRefus("REFUS-FABRIQUÉ-PAR-CE-BANC-52");
  exiger(c52.retirer.hidden === false,
    `(52c) une phrase de refus est affichée, sans date ni plage, et le bouton qui la retirerait n'est pas offert (${etat(c52)})`);
  c52.direLeRefus("");
  exiger(c52.retirer.hidden === true, `(52c) le refus est retiré et le bouton reste offert (${etat(c52)})`);

  // (d) DEUX VUES, UNE FENÊTRE : la plage est posée puis RETIRÉE par l'écrivain unique, sans qu'aucun
  //     geste ne touche ces barres. C'est le chemin qu'un correctif mal posé manque.
  const c52b = poserLeChoixDeDates("temoin-p11-20-f-voisine", cible52, porte52, () => {});
  exiger(c52b.retirer.hidden === true,
    `(52d-instrument) une barre posée sur une cible SANS plage arrive avec son retrait offert (${etat(c52b)}) : les deux barres ne partent pas du même état`);
  poserLaPlageSurLaCible(cible52, PLAGE_52);
  exiger(c52.debut.value === PLAGE_52.texteDebut && c52b.debut.value === PLAGE_52.texteDebut,
    `(52d-instrument) l'écrivain unique ne reflète pas la plage dans les deux barres (« ${c52.debut.value} » / « ${c52b.debut.value} ») : le chemin mesuré ici n'est pas celui qu'on croit`);
  exiger(c52.retirer.hidden === false && c52b.retirer.hidden === false,
    `(52d) une plage vient d'être posée par l'écrivain unique et le bouton qui la retirerait n'est pas offert (${etat(c52)} / ${etat(c52b)})`);
  poserLaPlageSurLaCible(cible52, null);
  exiger(cible52.lire() === null && c52.debut.value === "" && c52b.debut.value === "",
    "(52d-instrument) l'écrivain unique n'a pas retiré la plage : le quatrième chemin n'est pas celui qui est mesuré");
  exiger(c52.retirer.hidden === true && c52b.retirer.hidden === true,
    `(52d) L'AUTRE VUE A RETIRÉ LA PLAGE ET LE BOUTON RESTE OFFERT sur un contrôle qui n'a plus rien à retirer : le reflet ne passe pas par l'écrivain unique de la plage, et le remède est complice du défaut qu'il corrige (${etat(c52)} / ${etat(c52b)})`);

  // (e) LE MOTIF EST ÉCRIT DANS LES DEUX CAS, et les deux ne disent pas la même chose. Rien n'est
  //     recopié : les deux libellés sont DÉRIVÉS des deux états ci-dessus.
  exiger(!!MOTIF_INERTE_52 && !!MOTIF_ACTIF_52 && MOTIF_INERTE_52 !== MOTIF_ACTIF_52,
    `(52e) le bouton d'effacement ne dit pas ce qu'il fait dans les DEUX états : inerte « ${MOTIF_INERTE_52} », offert « ${MOTIF_ACTIF_52} »`);
  // (f) UN SEUL AVIS : `hidden` et `disabled` sortent du même prédicat, sur les quatre états parcourus.
  exiger(c52.retirer.hidden === c52.retirer.disabled && c52b.retirer.hidden === c52b.retirer.disabled,
    `(52f) le bouton est retiré et actif, ou offert et inerte : deux avis sur un même état (${etat(c52)} / ${etat(c52b)})`);

  console.log(`[retrait-derive] le bouton qui efface les dates est DÉRIVÉ de ce qu'il aurait à retirer, sur quatre états et deux barres posées sur la MÊME cible : absent à l'arrivée, offert dès qu'une date est frappée puis retiré quand elle est effacée, offert sur une phrase de refus seule, offert quand l'écrivain unique pose la plage et RETIRÉ quand une autre vue la retire — sans qu'aucun geste ne touche la barre. \`hidden\` et \`disabled\` ne se contredisent jamais, et le motif est écrit dans les deux états (${(MOTIF_INERTE_52 || "").length} / ${(MOTIF_ACTIF_52 || "").length} car., dérivés). CE QUE CE TÉMOIN NE TIENT PAS : le simulacre ne peint rien — que le retrait vaille mieux que le grisé tient à une feuille de style que ce témoin ne lit pas, et rien ici ne prouve qu'un exploitant VOIT le bouton disparaître.`);
}

// ---------------------------------------------------------------------------------------------
// 53. LES DEUX DERNIERS DÉPLIS ÉCRITS À LA MAIN PASSENT PAR LE GESTE COMMUN (`P11.20-j`, tenu par
//     `P11.8-h`).
//
//     CE QUI EST TENU, ET SEULEMENT CELA. Le constat d'origine a été RÉFUTÉ sur deux points, et ce
//     témoin ne les rouvre pas : les deux boutons n'en faisaient pas qu'un, et `aria-expanded` était
//     DÉJÀ posé — au repos par `index.html`, à chaque bascule par le code écrit à la main. Ce témoin
//     ne mesure donc PAS `aria-expanded` comme un gain : le mesurer ainsi ferait passer pour acquis
//     par le ralliement ce qui l'était avant lui. Le gain, mesuré, est ailleurs : `aria-controls` —
//     que `disclosure` pose DEPUIS l'identifiant du panneau et que ni la version à la main ni
//     `index.html` ne portaient — et la marque d'état `.on`, que le geste commun pose sur le bouton.
//
//     LE TÉMOIN EST PRIS SUR LES NŒUDS DE LA PAGE, pas sur un arbre fabriqué : ces deux câblages sont
//     posés à l'ÉVALUATION du module, sur les identifiants d'`index.html`, et c'est là qu'un
//     ralliement défait se verrait. Le clic est joué deux fois — la bascule se mesure, et l'état
//     d'origine est rendu au reste du banc.
// ---------------------------------------------------------------------------------------------
{
  const PANNEAUX_53 = [["#rule-collapse", "rule-list"], ["#parser-collapse", "parser-list"]];
  for (const [selBouton, idPanneau] of PANNEAUX_53) {
    const bouton = document.querySelector(selBouton), panneau = document.querySelector("#" + idPanneau);
    exiger(!!bouton && !!panneau && panneau.id === idPanneau,
      `(53-instrument) ${selBouton} ou #${idPanneau} n'est pas un nœud de la page : ce témoin jugerait un nœud détaché, et son vert ne dirait rien du câblage réel`);
    if (!bouton || !panneau || panneau.id !== idPanneau) continue;
    exiger(bouton.getAttribute("aria-controls") === idPanneau,
      `(53) ${selBouton} ne NOMME pas la région qu'il commande : \`aria-controls\` vaut « ${bouton.getAttribute("aria-controls")} » au lieu de « ${idPanneau} » — le dépli n'est pas passé par le geste commun, qui seul le pose depuis l'identifiant du panneau`);
    const ouvertAuRepos = !panneau.hidden;
    exiger(bouton.classList.contains("on") === ouvertAuRepos,
      `(53) ${selBouton} ne porte pas la marque d'état du geste commun : panneau ${ouvertAuRepos ? "ouvert" : "replié"}, classe « ${bouton.className} »`);
    // LA BASCULE, PAR LE CHEMIN RÉEL DU CLIC. Les trois valeurs changent ENSEMBLE ou le ralliement est
    // partiel — c'est ce que la version à la main ne tenait pas.
    bouton.dispatchEvent({ type: "click" });
    const bascule = { hidden: panneau.hidden, aria: bouton.getAttribute("aria-expanded"), on: bouton.classList.contains("on"), controls: bouton.getAttribute("aria-controls") };
    exiger(bascule.hidden === ouvertAuRepos && bascule.aria === (ouvertAuRepos ? "false" : "true") && bascule.on === !ouvertAuRepos && bascule.controls === idPanneau,
      `(53) un clic sur ${selBouton} ne fait pas bouger ensemble le pli, l'état annoncé et la marque : ${JSON.stringify(bascule)}`);
    bouton.dispatchEvent({ type: "click" });
    exiger(panneau.hidden === !ouvertAuRepos && bouton.classList.contains("on") === ouvertAuRepos && bouton.getAttribute("aria-controls") === idPanneau,
      `(53) un second clic sur ${selBouton} ne rend pas l'état d'origine : hidden=${panneau.hidden}, classe « ${bouton.className} »`);
  }

  // LE MODULE N'ÉCRIT PLUS SON PROPRE DÉPLI. Dérivé du source, comme le reste du fichier : un module
  // qui repose sur le geste commun n'a plus à poser `aria-expanded` lui-même.
  const srcDet53 = (CORPUS_WEB.find(([f]) => f === "detection_admin.js") || [])[1] || "";
  const codeDe53 = (src) => src.split("\n").filter((l) => !l.trim().startsWith("//"));
  const ariaEcrit53 = (src) => codeDe53(src).reduce((n, l) => n + (l.match(/aria-expanded/g) || []).length, 0);
  exiger(srcDet53.length > 0, "(53-instrument) `detection_admin.js` est introuvable dans le corpus : la mesure de source porte sur le vide");
  exiger(/\bdisclosure\b/.test(srcDet53) && (srcDet53.match(/disclosure\(/g) || []).length >= 1,
    "(53) `detection_admin.js` n'appelle plus le dépli partagé : les deux panneaux ont retrouvé un patron à eux");
  exiger(ariaEcrit53(srcDet53) === 0,
    `(53) \`detection_admin.js\` écrit ${ariaEcrit53(srcDet53)} fois \`aria-expanded\` dans son code : le patron de dépli est revenu à la main, et deux panneaux voisins ne se plient plus par le même geste`);
  // L'INSTRUMENT SE VALIDE SUR CE QUI EN CONTIENT : un compteur qui rend 0 partout ne prouverait rien.
  // LE COMPTEUR EST UNE BASCULE, PLUS UNE ÉCRITURE — corrigé le 2026-08-30, et la correction est
  // double. (1) `aria-expanded` ne DISCRIMINE PAS : il range du même côté la bascule écrite à la main
  // et la valeur AU REPOS d'un balisage rendu — que `index.html` porte lui aussi sur les deux boutons
  // ralliés ci-dessus, sans que personne y voie un dépli à la main. Ce qui ne ment pas est l'APPEL qui
  // bascule. (2) SURTOUT : la borne précédente EXIGEAIT qu'au moins un module porte encore le défaut,
  // « sinon le motif ne mesure plus rien ». Elle aurait donc rougi LE JOUR OÙ LE RALLIEMENT SERAIT
  // COMPLET — au moment exact où le travail est fini. Un témoin qui ne peut être vert que tant que le
  // chantier est ouvert n'est pas une garde, c'est une rançon. L'auto-validation porte désormais sur
  // des chaînes FABRIQUÉES ici : le compteur se prouve sur elles, et ne dépend plus de l'état du dépôt.
  const basculeAlaMain53 = (src) => codeDe53(src).reduce((n, l) => n + (l.match(/setAttribute\(\s*["']aria-expanded["']/g) || []).length, 0);
  exiger(basculeAlaMain53("b.setAttribute('aria-expanded', 'true');") === 1
      && basculeAlaMain53("  // b.setAttribute('aria-expanded', 'true');") === 0
      && basculeAlaMain53("<button aria-expanded=\"false\">") === 0,
    `(53-instrument) le compteur de bascule ne distingue pas une bascule écrite à la main d'un commentaire ni d'une valeur au repos dans du balisage : son compte ne mesure rien`);
  const resteAlaMain53 = CORPUS_WEB.filter(([f, src]) => f.endsWith(".js") && f !== "core.js" && basculeAlaMain53(src) > 0).map(([f]) => f).sort();
  exiger(JSON.stringify(resteAlaMain53) === JSON.stringify(["alerts.js"]),
    `(53-borne) les modules qui BASCULENT encore leur dépli à la main ont changé : ${JSON.stringify(resteAlaMain53)} au lieu du seul mesuré le 2026-08-30. Un module de plus est une régression ; un module de moins est un reste FERMÉ — dans les deux cas, cette borne se remesure et se réécrit, elle n'exige plus que le défaut subsiste.`);

  console.log(`[depli-commun] les deux panneaux d'administration de la détection passent par le geste commun : chaque bouton NOMME sa région (\`aria-controls\` = l'identifiant du panneau, que ni la version à la main ni index.html ne posaient), porte la marque d'état du geste, et un clic joué sur le nœud de la page fait bouger ensemble le pli, l'état annoncé et la marque — deux fois, l'état d'origine rendu. \`aria-expanded\` n'est PAS compté comme un gain : il était déjà posé avant le ralliement. CE QUE CE TÉMOIN NE TIENT PAS : le ralliement n'est pas général — ${resteAlaMain53.length} module(s) de web/ écrivent encore leur dépli à la main (${resteAlaMain53.join(", ")}), et cette borne le dit au lieu de le taire ; et rien ici ne prouve qu'une assistance technique RÉELLE lise ces attributs.`);
}

// ---------------------------------------------------------------------------------------------
// 54. LES DEUX PLIAGES DE LA FRAÎCHEUR PASSENT PAR LE GESTE COMMUN, ET CE QUI RESTE À LA MAIN EST
//     NOMMÉ PAR SA FORME (`P11.21-b`, tenu par `P11.8-h`).
//
//     CE QUE LE CONSTAT DISAIT, ET CE QUE LA MESURE DU 2026-08-30 EN CORRIGE. Il annonçait HUIT sites
//     de dépli écrits à la main dans DEUX modules. Le compte de huit est EXACT si l'on compte les
//     ÉCRITURES d'`aria-expanded` hors commentaire ; il ne l'est pas si l'on compte des MÉCANISMES —
//     il y en avait TROIS : deux dans `freshness.js` (les groupes par état, les séries métriques) et
//     UN dans `alerts.js` (les groupes d'alertes). Ce témoin ne mesure donc PAS `aria-expanded` comme
//     un gain : il était DÉJÀ posé, au repos par le balisage rendu et à chaque bascule par le code
//     écrit à la main. Le gain mesuré est `aria-controls` — que `disclosure` pose depuis
//     l'identifiant du panneau et que ni la version à la main ni le balisage ne portaient — plus la
//     marque d'état `.on`, INERTE à l'écran (aucune règle de la feuille ne vise `.fgrouphd.on` ni
//     `.fmetrichd.on`) et lisible par le programme seul.
//
//     LE TÉMOIN EST PRIS SUR LES NŒUDS QUE `renderFreshness` CONSTRUIT, pas sur un arbre fabriqué :
//     le câblage n'existe QUE là, et c'est là qu'un ralliement défait se verrait. `fetch` est absent
//     de ce banc par construction ; il est posé LE TEMPS de ce témoin et rendu ensuite, faute de quoi
//     le panneau ne serait jamais peint. Le clic est joué deux fois — la bascule se mesure, et l'état
//     d'origine est rendu au reste du banc.
//
//     ET CE QUI N'EST PAS RALLIÉ EST MESURÉ SUR LA BASCULE, PAS SUR L'ÉCRITURE. Compter les écritures
//     d'`aria-expanded` rangerait du même côté la BASCULE écrite à la main et la valeur AU REPOS d'un
//     balisage — que `index.html` porte lui aussi sur les deux boutons ralliés par `P11.20-j`, sans
//     que personne y voie un dépli à la main. Le reste se mesure donc sur `setAttribute`.
// ---------------------------------------------------------------------------------------------
{
  const { renderFreshness } = await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const { S: S54 } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const FEEDS_54 = [
    { kind: "event", name: "kube-audit", status: "en_retard", age_s: 1500, last_seen: 1000, n_24h: 5000, active_alerts: 0, cadence_declaree: "continue", cadence_interval_s: 120, cadence_capteur: "kube-audit" },
    { kind: "event", name: "mail", status: "calme", age_s: 3960, last_seen: 1000, n_24h: 96, active_alerts: 0, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null },
    { kind: "metric", name: "métriques · 1 série", status: "frais", age_s: 20, last_seen: 1000, n_24h: 900, active_alerts: 0, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, series: [{ name: "cpu", status: "frais", age_s: 20, last_seen: 1000 }] },
  ];
  const fetchOrigine54 = globalThis.fetch, plisOrigine54 = S54.freshCollapsed;
  globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ pipeline_fresh: true, feeds: FEEDS_54 }) });
  S54.freshCollapsed = new Set(["cat:calme"]);
  try { await renderFreshness(); } finally { globalThis.fetch = fetchOrigine54; }

  const corps54 = document.querySelector("#freshness-panel .body");
  exiger(!!corps54 && corps54.isConnected, "(54-instrument) `#freshness-panel .body` n'est pas un nœud RATTACHÉ de la page : ce témoin jugerait un arbre détaché, et son vert ne dirait rien du câblage réel");
  const entetes54 = corps54 ? corps54.querySelectorAll(".fgrouphd") : [];
  exiger(entetes54.length >= 2, `(54-instrument) la fraîcheur n'a rendu que ${entetes54.length} groupe(s) d'état : sous deux, ce témoin ne mesure pas un pliage, il mesure un panneau vide`);
  for (const hd of entetes54) {
    const env = hd.closest(".fgroup"), panneau = env && env.querySelector(".fgbody"), cat = env ? env.dataset.cat : "?";
    exiger(!!panneau && panneau.id === "fgbody-" + cat,
      `(54) le panneau du groupe « ${cat} » ne porte pas l'identifiant dérivé de son état : « ${panneau && panneau.id} » — sans identifiant, le geste commun ne peut NOMMER aucune région`);
    exiger(hd.getAttribute("aria-controls") === (panneau && panneau.id),
      `(54) l'en-tête du groupe « ${cat} » ne NOMME pas la région qu'il commande : \`aria-controls\` vaut « ${hd.getAttribute("aria-controls")} » au lieu de « fgbody-${cat} »`);
    const ouvert54 = !env.classList.contains("collapsed");
    exiger(hd.classList.contains("on") === ouvert54,
      `(54) l'en-tête du groupe « ${cat} » ne porte pas la marque d'état du geste commun : groupe ${ouvert54 ? "déplié" : "replié"}, classe « ${hd.className} »`);
    hd.dispatchEvent({ type: "click" });
    const apres54 = { pli: !env.classList.contains("collapsed"), aria: hd.getAttribute("aria-expanded"), on: hd.classList.contains("on"), memoire: S54.freshCollapsed.has("cat:" + cat) };
    exiger(apres54.pli === !ouvert54 && apres54.aria === (ouvert54 ? "false" : "true") && apres54.on === !ouvert54 && apres54.memoire === ouvert54,
      `(54) un clic sur le groupe « ${cat} » ne fait pas bouger ENSEMBLE le pli, l'état annoncé, la marque et la mémoire : ${JSON.stringify(apres54)}`);
    hd.dispatchEvent({ type: "click" });
    exiger(!env.classList.contains("collapsed") === ouvert54 && hd.getAttribute("aria-expanded") === (ouvert54 ? "true" : "false") && hd.classList.contains("on") === ouvert54 && S54.freshCollapsed.has("cat:" + cat) === !ouvert54,
      `(54) un second clic sur le groupe « ${cat} » ne rend pas l'état d'origine : pli « ${env.className} », bouton « ${hd.className} », mémoire ${JSON.stringify([...S54.freshCollapsed])}`);
  }
  const md54 = corps54 ? corps54.querySelector(".fmetrichd") : null;
  exiger(!!md54, "(54-instrument) l'en-tête des séries métriques n'a pas été rendu : la moitié de ce témoin jugerait le vide");
  if (md54) {
    const env = md54.closest(".fmetric"), pan = env && env.querySelector(".fmetricbody"), ouvert = !env.classList.contains("collapsed");
    exiger(md54.classList.contains("on") === ouvert,
      `(54) l'en-tête des séries métriques ne porte pas la marque d'état du geste commun : séries ${ouvert ? "dépliées" : "repliées"}, classe « ${md54.className} »`);
    // CE QUI N'EST PAS GAGNÉ ICI EST TENU COMME TEL, PAS TU : le panneau des séries n'a pas d'identité
    // dérivable (`rowOf` rendrait un en-tête par flux métrique, ce câblage n'équipe que le PREMIER, et
    // l'unicité d'un identifiant fixe dépendrait d'une propriété de la charge utile du démon — un seul
    // flux `kind:"metric"` — que la console ne vérifie jamais). Le jour où cette identité existe, c'est
    // CE témoin qu'il faut mettre à jour, pas la clé qu'il faut rouvrir en silence.
    exiger(!pan.id && md54.getAttribute("aria-controls") === null,
      `(54-borne) le panneau des séries métriques a reçu un identifiant (« ${pan.id} ») : \`aria-controls\` est donc gagnable ici, mettez ce témoin à jour au lieu de laisser sa borne mentir`);
    exiger(md54.getAttribute("role") === "button" && md54.getAttribute("tabindex") === "0",
      "(54) l'en-tête des séries métriques n'est plus atteignable au clavier : ce n'est pas un `<button>`, rien ne l'active nativement");
    md54.dispatchEvent({ type: "click" });
    exiger(!env.classList.contains("collapsed") === !ouvert && md54.getAttribute("aria-expanded") === (ouvert ? "false" : "true") && md54.classList.contains("on") === !ouvert,
      `(54) un clic sur les séries métriques ne fait pas bouger ensemble le pli, l'état annoncé et la marque : « ${env.className} » / « ${md54.className} »`);
    md54.dispatchEvent({ type: "keydown", key: "Enter" });
    exiger(!env.classList.contains("collapsed") === ouvert && md54.getAttribute("aria-expanded") === (ouvert ? "true" : "false") && md54.classList.contains("on") === ouvert,
      `(54) la touche Entrée ne rend pas l'état d'origine des séries métriques : cet en-tête n'est PAS un \`<button>\`, aucune activation native ne rattrape un clavier débranché`);
  }
  S54.freshCollapsed = plisOrigine54;

  // CE QUI RESTE ÉCRIT À LA MAIN, MESURÉ SUR LA BASCULE.
  const codeDe54 = (src) => src.split("\n").filter((l) => !l.trim().startsWith("//"));
  const basculeAlaMain54 = (src) => codeDe54(src).reduce((n, l) => n + (l.match(/setAttribute\(\s*["']aria-expanded["']/g) || []).length, 0);
  // L'INSTRUMENT SE VALIDE SUR CE QU'IL LIT, JAMAIS SUR CE QUI RESTE À FAIRE. La validation de la
  // section 53 (« le compteur doit trouver au moins un site ») EXIGE qu'un module de `web/` porte
  // encore le défaut : elle rougirait le jour où le ralliement serait COMPLET, c'est-à-dire au moment
  // même où le travail est fini. Celle-ci est faite sur trois chaînes fabriquées, dans les deux sens.
  exiger(basculeAlaMain54("b.setAttribute('aria-expanded', 'true');") === 1
      && basculeAlaMain54("  // b.setAttribute('aria-expanded', 'true');") === 0
      && basculeAlaMain54("<button aria-expanded=\"false\">") === 0,
    "(54-instrument) le compteur de bascule ne distingue pas une bascule écrite à la main d'un commentaire ni d'une valeur au repos dans du balisage : son compte ne mesure rien");
  const srcFrais54 = (CORPUS_WEB.find(([f]) => f === "freshness.js") || [])[1] || "";
  exiger(srcFrais54.length > 0, "(54-instrument) `freshness.js` est introuvable dans le corpus : la mesure de source porte sur le vide");
  exiger((srcFrais54.match(/disclosure\(/g) || []).length >= 2,
    "(54) `freshness.js` n'appelle plus le dépli partagé sur ses DEUX pliages : un patron à lui est revenu à côté du geste commun");
  exiger(basculeAlaMain54(srcFrais54) === 0,
    `(54) \`freshness.js\` écrit ${basculeAlaMain54(srcFrais54)} bascule(s) \`aria-expanded\` à la main : le patron de dépli est revenu, et deux pliages voisins ne se font plus par le même geste`);
  const resteAlaMain54 = CORPUS_WEB.filter(([f, src]) => f.endsWith(".js") && f !== "core.js" && basculeAlaMain54(src) > 0).map(([f]) => f).sort();
  exiger(JSON.stringify(resteAlaMain54) === JSON.stringify(["alerts.js"]),
    `(54-borne) les modules qui écrivent encore la BASCULE du dépli à la main ont changé : ${JSON.stringify(resteAlaMain54)} au lieu du seul mesuré le 2026-08-30. Un module de plus est une RÉGRESSION ; un de moins est un reste fermé — mettez cette borne à jour dans ce cas, elle ne se corrige pas toute seule.`);

  console.log(`[depli-fraicheur] les DEUX pliages du panneau Fraîcheur passent par le geste commun : chaque en-tête de groupe d'état NOMME sa région (\`aria-controls\` = \`fgbody-<état>\`, dérivé du vocabulaire fermé des états, que ni la version à la main ni le balisage ne posaient), porte la marque d'état du geste, et un clic joué sur les nœuds que \`renderFreshness\` construit fait bouger ensemble le pli, l'état annoncé, la marque et la mémoire du pli — deux fois, l'état d'origine rendu ; l'en-tête des séries métriques, qui n'est PAS un \`<button>\`, garde son clavier porteur et bascule par le même geste. \`aria-expanded\` n'est PAS compté comme un gain : il était déjà posé avant le ralliement. CE QUE CE TÉMOIN NE TIENT PAS : la marque \`.on\` est INERTE à l'écran (aucune règle de la feuille ne la vise sur ces deux en-têtes) ; \`aria-controls\` n'est PAS gagné sur les séries métriques, faute d'identité dérivable, et la borne ci-dessus le dit ; le ralliement n'est pas général — ${resteAlaMain54.length} module(s) écrivent encore la bascule à la main (${resteAlaMain54.join(", ")}) ; et rien ici ne prouve qu'une assistance technique RÉELLE lise ces attributs.`);
}


// ---------------------------------------------------------------------------------------------
// 55. UNE PAGE INCOMPLÈTE N'EST PAS UN REFUS — SUR LES TROIS VUES QUI JETAIENT CE QU'ELLES AVAIENT
//     REÇU (`P11.21-i`).
//
//     POURQUOI CE TÉMOIN EXISTE, ET IL NE DOUBLE PAS LE 51. Le témoin 51 tient DEUX issues sur trois :
//     un refus ne se rend ni en panne constatée ni en absence établie. Il ne dit RIEN de la troisième,
//     et c'est précisément celle que `P10.7-f` a créée côté démon — un corps qui porte des LIGNES ET une
//     CAUSE. Sur ce corps-là, les trois vues prenaient la branche du refus : elles JETAIENT ce qu'elles
//     avaient reçu. La pire (`attack.js`) annonçait qu'aucune technique n'avait été lue alors que la
//     cause servie déclare la couverture ÉTABLIE — un verdict de couverture purple faux DEUX fois.
//
//     L'INSTRUMENT SE VALIDE SUR LE DÉMON, ET C'EST CE QUI EMPÊCHE UN VERT PAR CONSTRUCTION. Nourrir la
//     console d'un corps FABRIQUÉ « lignes + cause » prouverait seulement qu'elle gère un cas — pas que
//     ce cas existe. Les trois voies d'aveu sont donc LUES dans l'arbre du démon, et le témoin refuse de
//     conclure si l'une disparaît : le jour où une route cesse de pouvoir tronquer, ce témoin rougit et
//     demande qu'on le mette à jour, au lieu de rester vert sur une propriété devenue vide.
//
//     ET L'AVEU DOIT ÊTRE CONDITIONNEL : le chemin NOMINAL est exercé le premier, et un aveu qui s'y
//     rendrait est un ÉCHEC — un corps qui avoue toujours n'avoue rien.
//
//     CE QU'IL NE TIENT PAS : il juge le TEXTE d'un arbre (ou d'une chaîne de balisage), jamais ce qu'un
//     moteur de rendu en peint ; il ne dit rien de la POSITION visuelle de l'aveu, seulement de son rang
//     dans l'ordre du document ; et il n'exerce pas la troisième route du démon qui sait tronquer
//     (`/api/alerts`), tenue par le témoin de `P11.21-h`.
// ---------------------------------------------------------------------------------------------
{
  const CAUSE_55 = "CAUSE-DE-TRONCATURE-FABRIQUÉE-PAR-CE-BANC-55 : aucune phrase du démon n'est citée ici";
  const srcAlertes55 = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "alerts.rs"), "utf8");
  const srcFrais55 = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "freshness.rs"), "utf8");
  // — instrument : LES TROIS VOIES D'AVEU EXISTENT, ET ELLES SONT STRICTEMENT CONDITIONNELLES.
  const voieConditionnelle = (src, fn) => {
    const m = src.match(new RegExp("fn " + fn + "\\([\\s\\S]*?\\n\\}"));
    return !!m && /if let Some\((?:cause|phrase)\)/.test(m[0]) && /\["error"\]/.test(m[0]);
  };
  exiger(voieConditionnelle(srcAlertes55, "corps_de_matrice_attack"),
    "(55-instrument) `corps_de_matrice_attack` n'ajoute plus une cause CONDITIONNELLE à une matrice servie — la propriété que ce témoin tient n'a plus d'objet, mettez-le à jour au lieu de le laisser vert");
  exiger(voieConditionnelle(srcAlertes55, "corps_de_couverture_des_detections"),
    "(55-instrument) `corps_de_couverture_des_detections` n'ajoute plus une cause CONDITIONNELLE à des détections servies");
  exiger(/if let Some\(phrase\) = releve\.aveu\(\)/.test(srcFrais55) && /corps\["error"\] = json!\(phrase\)/.test(srcFrais55),
    "(55-instrument) `compute_freshness` ne pose plus l'aveu de racine du relevé : la vue de fraîcheur n'a plus de cause à lire");
  exiger(/corps\["imputation_des_alertes"\]\["error"\]/.test(srcFrais55),
    "(55-instrument) l'aveu IMBRIQUÉ du partage des alertes a disparu du démon : la moitié du témoin jugerait le vide");

  const rendre55 = async (module, nomExport, selecteur, corps) => {
    const hote = new Element("div"), leg = new Element("div");
    const qs = document.querySelector, fx = globalThis.fetch;
    document.querySelector = (s) => (s === selecteur ? hote : s === "#attack-legend" ? leg : qs(s));
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify(corps) });
    try { const m = await import(pathToFileURL(path.join(WEB, module)).href); await m[nomExport](); }
    finally { document.querySelector = qs; globalThis.fetch = fx; }
    return hote;
  };

  // --- (a) LA MATRICE ATT&CK : le pire cas — une cause qui déclare la couverture ÉTABLIE. ---
  const TAC55 = { tactic: "discovery", rule_count: 1, covered: true, techniques: [
    { tid: "T1046", name: "Network Service Discovery", covered: true, rule_count: 1, alert_count: 0 },
    { tid: "T1018", name: "Remote System Discovery", covered: false, rule_count: 0, alert_count: 0 }] };
  const cellules55 = (n) => n.querySelectorAll(".attack-cell").length;
  const matEntiere = await rendre55("attack.js", "loadAttackMatrix", "#attack-body", { tactics: [TAC55], totals: {} });
  const matPartielle = await rendre55("attack.js", "loadAttackMatrix", "#attack-body", { tactics: [TAC55], totals: {}, error: CAUSE_55 });
  const matRefus = await rendre55("attack.js", "loadAttackMatrix", "#attack-body", { tactics: [], totals: {}, error: CAUSE_55 });
  exiger(cellules55(matEntiere) === 2,
    `(55a-instrument) une matrice SERVIE ne rend pas ses techniques (${cellules55(matEntiere)} cellule(s)) : ce témoin ne pourrait pas rougir`);
  exiger(!matEntiere.textContent.includes(CAUSE_55),
    "(55a-instrument) une lecture ENTIÈRE rend quand même la cause : la dérivation lit autre chose que ce qu'elle croit");
  const AVEU_55 = matPartielle.children[0] ? matPartielle.children[0].textContent : "";
  exiger(AVEU_55.includes(CAUSE_55),
    `(55a) L'AVEU N'OUVRE PAS LE RENDU : un lecteur qui va de haut en bas le rencontrerait APRÈS la matrice, donc après avoir compté des alertes qui sont des SOUS-COMPTES. Premier nœud : « ${AVEU_55} »`);
  exiger(!matEntiere.textContent.includes(AVEU_55.slice(0, 40)),
    "(55a) LE CHEMIN NOMINAL PORTE L'AVEU : un corps qui avoue toujours n'avoue rien, et cette surface cesserait de distinguer une lecture entière d'un préfixe");
  exiger(cellules55(matPartielle) === cellules55(matEntiere),
    `(55a) LA MATRICE EST JETÉE SUR UN CORPS QUI LA PORTE : ${cellules55(matPartielle)} cellule(s) rendues au lieu de ${cellules55(matEntiere)}. La cause servie déclare la couverture ÉTABLIE ; annoncer qu'aucune technique n'a été lue est un verdict de couverture FAUX`);
  exiger(cellules55(matRefus) === 0 && matRefus.textContent.includes(CAUSE_55),
    "(55a) un REFUS (aucune tactique servie) ne rend plus le refus, ou n'en nomme plus la cause");
  exiger(new Set([matEntiere.textContent, matPartielle.textContent, matRefus.textContent]).size === 3,
    "(55a) les trois issues de la matrice (entière, partielle, refus) ne rendent pas trois textes distincts");

  // --- (b) LA COUVERTURE PAR DÉTECTIONS : même triplet, plus le VRAI vide, qui reste une absence. ---
  const DET55 = [{ mitre: "T1059", count: 2, first_ts: 1800000000 }, { mitre: "T1046", count: 1, first_ts: 1800000000 }];
  const puces55 = (n) => (n.innerHTML.match(/mitrechip/g) || []).length;
  const covEntiere = await rendre55("detection_admin.js", "renderCoverage", "#cov-body", { detections: DET55 });
  const covPartielle = await rendre55("detection_admin.js", "renderCoverage", "#cov-body", { detections: DET55, error: CAUSE_55 });
  const covRefus = await rendre55("detection_admin.js", "renderCoverage", "#cov-body", { detections: [], error: CAUSE_55 });
  const covVide = await rendre55("detection_admin.js", "renderCoverage", "#cov-body", { detections: [] });
  exiger(puces55(covEntiere) === 2 && !covEntiere.innerHTML.includes(CAUSE_55),
    `(55b-instrument) une couverture SERVIE ne rend pas ses techniques, ou rend une cause qu'elle n'a pas (${puces55(covEntiere)} puce(s))`);
  exiger(puces55(covPartielle) === puces55(covEntiere),
    `(55b) LES TECHNIQUES SONT JETÉES SUR UN CORPS QUI LES PORTE : ${puces55(covPartielle)} puce(s) au lieu de ${puces55(covEntiere)}`);
  exiger(covPartielle.innerHTML.startsWith('<div class="bad">') && covPartielle.innerHTML.includes(CAUSE_55),
    "(55b) l'aveu n'ouvre pas le rendu de la couverture, ou n'y colle pas la cause du démon");
  exiger(puces55(covRefus) === 0 && covRefus.innerHTML.includes(CAUSE_55),
    "(55b) un refus de lire la couverture ne se distingue plus de la lecture partielle");
  exiger(!covVide.innerHTML.includes(CAUSE_55) && covVide.innerHTML !== covRefus.innerHTML,
    "(55b) LE VRAI VIDE ET LE REFUS SE CONFONDENT : c'est exactement le défaut que le témoin 51 ferme, revenu par l'autre bout");

  // --- (c) LA FRAÎCHEUR : la route la plus souvent servie, et le défaut y allait dans l'autre sens —
  //         un relevé TRONQUÉ rendu comme COMPLET, sans un mot. ---
  const { renderFreshnessDetail: detail55 } = await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const FLUX55 = [{ name: "syslog", kind: "event", age_s: 30, last_seen: 1800000000, status: "frais" },
                  { name: "auditd", kind: "event", age_s: 40, last_seen: 1800000000, status: "frais" }];
  const IMP55 = { actives: 5, avec_cloche: 3, sans_source_nommee: 1, sans_imputation: 1, jeton_sans_source: "(source indéterminée)" };
  const lignes55 = (h) => (h.match(/class="kv"/g) || []).length;
  const frEntier = detail55({ feeds: FLUX55, pipeline_fresh: true, imputation_des_alertes: IMP55 });
  const frPartiel = detail55({ feeds: FLUX55, pipeline_fresh: true, imputation_des_alertes: IMP55, error: CAUSE_55 });
  exiger(lignes55(frEntier) >= 2 && !frEntier.includes(CAUSE_55),
    `(55c-instrument) le détail ne rend pas ses flux, ou rend une cause qu'il n'a pas (${lignes55(frEntier)} ligne(s))`);
  exiger(frPartiel.startsWith('<div class="bad">') && frPartiel.includes(CAUSE_55),
    "(55c) LE RELEVÉ TRONQUÉ EST RENDU COMME UN RELEVÉ COMPLET : la cause servie n'atteint pas l'écran, et l'exploitant ne peut pas soupçonner qu'il manque des flux");
  exiger(lignes55(frPartiel) === lignes55(frEntier),
    "(55c) les flux servis ne sont plus rendus sur un relevé partiel : le sens de l'erreur s'est inversé dans l'autre direction");
  // L'aveu IMBRIQUÉ du partage vit DANS son sous-objet, et il a ses deux issues à lui.
  const frImp = detail55({ feeds: FLUX55, pipeline_fresh: true, imputation_des_alertes: { ...IMP55, error: CAUSE_55 } });
  const frImpRefus = detail55({ feeds: FLUX55, pipeline_fresh: true, imputation_des_alertes: { actives: 0, avec_cloche: 0, sans_source_nommee: 0, sans_imputation: 0, jeton_sans_source: "x", error: CAUSE_55 } });
  exiger(!frEntier.includes(CAUSE_55) && frImp.includes(CAUSE_55) && /5<\/b> alerte/.test(frImp),
    "(55c) le partage des alertes ne rend pas SA cause À CÔTÉ de ses quatre nombres : une somme qui a l'air juste et porte sur moins d'alertes qu'il n'y en a");
  exiger(frImpRefus.includes(CAUSE_55),
    "(55c) un partage dont RIEN n'a été compté reste MUET : l'absence du bloc se lit « aucune alerte active », qui est le fait le plus rassurant de cette vue");
  // Les deux chargeurs de vue, sur un corps SANS flux et AVEC une cause.
  const pulseRefus = await rendre55("freshness.js", "renderFreshnessPulse", "#freshness .body", { feeds: [], pipeline_fresh: true, error: CAUSE_55 });
  const pulseVide = await rendre55("freshness.js", "renderFreshnessPulse", "#freshness .body", { feeds: [], pipeline_fresh: true });
  const detailRefus = await rendre55("freshness.js", "renderFreshness", "#freshness-panel .body", { feeds: [], pipeline_fresh: true, error: CAUSE_55 });
  const PHRASE_DE_VIDE_55 = pulseVide.innerHTML;
  exiger(PHRASE_DE_VIDE_55.length > 20 && !PHRASE_DE_VIDE_55.includes(CAUSE_55),
    `(55c-instrument) la phrase de référence du VRAI vide n'est pas dérivable (« ${PHRASE_DE_VIDE_55} »)`);
  exiger(pulseRefus.innerHTML.includes(CAUSE_55) && !pulseRefus.innerHTML.includes(PHRASE_DE_VIDE_55),
    `(55c) LE PULSE REND UN REFUS COMME UNE ABSENCE — et c'est la charge VIVE de la vue d'arrivée, donc la plus souvent lue de tout ce lot. Rendu : « ${pulseRefus.innerHTML} »`);
  exiger(detailRefus.innerHTML.includes(CAUSE_55) && !detailRefus.innerHTML.includes(PHRASE_DE_VIDE_55),
    `(55c) LE DÉTAIL DE LA FRAÎCHEUR REND UN REFUS COMME UNE ABSENCE. Rendu : « ${detailRefus.innerHTML} »`);

  console.log(`[page-incomplete-pas-refus] trois vues, trois issues chacune sur le corps que le démon sert VRAIMENT : la matrice ATT&CK rend ses ${cellules55(matPartielle)} technique(s) sous un aveu au lieu de les jeter (elle en jetait toutes, sur une cause qui déclare la couverture ÉTABLIE), la couverture par détections rend ses ${puces55(covPartielle)} technique(s) et distingue encore le VRAI vide du refus, et la fraîcheur — dont le défaut allait dans l'AUTRE sens, un relevé tronqué servi comme complet — avoue à la racine, dans le partage des alertes, et sur ses deux chargeurs de vue. Les TROIS voies d'aveu sont LUES dans le démon et non supposées : si l'une cesse d'être conditionnelle, ce témoin refuse de conclure. Le chemin NOMINAL est exercé le premier et ne porte AUCUN aveu — un corps qui avoue toujours n'avoue rien. Aucune phrase du démon n'est recopiée : la cause injectée est visiblement fabriquée. CE QUE CE TÉMOIN NE TIENT PAS : il juge le TEXTE d'un arbre, jamais ce qu'un moteur de rendu en peint ; il ne dit rien de la position VISUELLE de l'aveu, seulement de son rang dans le document ; et il n'exerce pas /api/alerts, tenu par le témoin de \`P11.21-h\`.`);
}

// ---------------------------------------------------------------------------------------------
// 56. UN POPOVER ANCRÉ TIENT DANS L'ÉCRAN, ET LE FAIRE DÉFILER NE LE FERME PAS (`P11.22-z`).
//
//     LE CONSTAT D'EXPLOITANT ÉTAIT UN SYMPTÔME VRAI SUR UNE CAUSE FAUSSE, et ce témoin tient les DEUX
//     causes réelles parce qu'elles sont indépendantes et qu'un correctif peut défaire l'une sans l'autre.
//
//     (1) LA BORNE NE BORNAIT PAS CE QU'ON CROYAIT. Une hauteur exprimée en fraction de FENÊTRE limite la
//     HAUTEUR d'une boîte à position fixe, JAMAIS sa POSITION : ancre en bas d'écran, la boîte descendait
//     de plusieurs centaines de pixels HORS ÉCRAN — sans erreur, ET SANS BARRE DE DÉFILEMENT, puisque le
//     contenu tenait sous le plafond. Rien ne débordait DE LA BOÎTE ; c'est la boîte qui débordait de l'écran.
//
//     (2) LA LISTE SE FERMAIT AU LIEU DE DÉFILER. Le capteur de défilement est posé sur le document en
//     phase de CAPTURE — ce qui est NÉCESSAIRE pour voir un défilement dans un conteneur imbriqué — mais
//     il recevait alors le défilement DE SA PROPRE LISTE. Le remède n'est donc PAS de retirer la capture :
//     c'est que le gestionnaire IGNORE ce qui vient de son propre popover. Ce témoin exige la garde, pas
//     l'absence du capteur — et il attrape aussi LE REMÈDE POUSSÉ TROP LOIN, un capteur qui ne ferme plus rien.
//
//     CE QU'IL NE TIENT PAS : il lit ce que le module POSE, jamais l'encre peinte. Une borne déplacée dans
//     la feuille de style le ferait rougir à tort ; une borne posée en pixels puis écrasée par une règle
//     prioritaire le laisserait vert. Il juge la BOÎTE, jamais son CONTENU : il ne dit rien du nombre de
//     colonnes qui tiennent dedans. Et il ne rejoue AUCUN redimensionnement de fenêtre, popover ouvert —
//     limite que le geste commun déclare lui-même.
// ---------------------------------------------------------------------------------------------
{
  const modNoyau56 = await import(pathToFileURL(path.join(WEB, "core.js")).href);
  const borner56 = modNoyau56.bornerLePopoverSousSonAncre;

  // — instrument : LE GESTE EXISTE ET REND LES DEUX GRANDEURS QU'UN TÉMOIN PEUT LIRE SANS DEVINER.
  exiger(typeof borner56 === "function",
    "(56-instrument) le geste commun de bornage des popovers a disparu de core.js : ce témoin n'a plus d'objet, mettez-le à jour au lieu de le laisser vert");
  const sondeInstrument56 = borner56({ style: {} }, { top: 100, bottom: 140 });
  exiger(sondeInstrument56 && typeof sondeInstrument56.hauteurMax === "number" && typeof sondeInstrument56.versLeHaut === "boolean",
    "(56-instrument) le geste commun ne rend plus `{versLeHaut, hauteurMax}` : les jambes qui suivent devineraient au lieu de lire");

  // — jambe A, EXÉCUTÉE : la boîte tient dans l'écran, quelle que soit la hauteur de l'ancre.
  const H56 = window.innerHeight;
  const boite56 = (bas) => {
    const el = { style: {} };
    const r = borner56(el, { top: bas - 22, bottom: bas });
    const h = parseInt(el.style.maxHeight, 10);
    const haut = r.versLeHaut ? (H56 - parseInt(el.style.bottom, 10) - h) : parseInt(el.style.top, 10);
    return { haut, bas: haut + h, hauteurMax: h, versLeHaut: r.versLeHaut, el };
  };
  exiger(H56 > 200, `(56a-instrument) la fenêtre du simulacre fait ${H56}px : trop courte pour que « hors écran » veuille dire quelque chose`);
  for (const bas of [60, Math.round(H56 / 2), H56 - 88]) {
    const b = boite56(bas);
    exiger(b.bas <= H56 && b.haut >= 0,
      `(56a) LE POPOVER SORT DE L'ÉCRAN : ancre à ${bas}px d'une fenêtre de ${H56}px, la boîte occupe ${b.haut}..${b.bas}px, soit ${Math.max(0, b.bas - H56)}px sous le bord. Une borne en fraction de FENÊTRE limite la HAUTEUR, jamais la POSITION`);
    exiger(b.el.style.overflowY === "auto",
      `(56a) le popover ne peut pas défiler à l'intérieur (ancre ${bas}px) : borner sa hauteur sans lui rendre son débordement CACHE les dernières entrées au lieu de les rendre atteignables`);
    exiger(b.hauteurMax > 0,
      `(56a) hauteur utile nulle pour une ancre à ${bas}px : le popover serait borné à l'invisible`);
  }
  const basse56 = boite56(H56 - 20), haute56 = boite56(60);
  exiger(basse56.versLeHaut && !haute56.versLeHaut,
    `(56a) la bascule au-dessus de l'ancre ne suit pas l'espace disponible (ancre basse -> versLeHaut=${basse56.versLeHaut}, ancre haute -> ${haute56.versLeHaut}) : sans elle, une ancre en bas d'écran ne laisse QUE le débordement`);

  // — jambe B, DÉRIVÉE : un capteur de défilement en phase de CAPTURE doit IGNORER son propre popover.
  //   LE CORPS DU GESTIONNAIRE EST DÉLIMITÉ PAR COMPTAGE, PAS PAR UNE FENÊTRE DE CARACTÈRES, ET C'EST UNE
  //   CORRECTION MESURÉE DU 2026-08-30 : un premier jet lisait 400 caractères après la déclaration, si bien
  //   qu'il débordait sur le code VOISIN et y trouvait toujours de quoi s'acquitter. La jambe qui exigeait
  //   qu'un capteur ferme quelque chose était VERTE PAR CONSTRUCTION — éprouvée par la mutation qui aurait
  //   dû la faire rougir, elle est restée muette. On délimite donc le corps par équilibrage des accolades
  //   et des parenthèses, depuis le signe d'affectation jusqu'au point-virgule de profondeur zéro.
  const corpsDuGestionnaire56 = (src, nom) => {
    const m = new RegExp("(?:const|let|var)\\s+" + nom + "\\s*=").exec(src);
    if (!m) {
      const f = new RegExp("function\\s+" + nom + "\\s*\\(").exec(src);
      if (!f) return null;
      let k = src.indexOf("{", f.index), d = 0;
      for (let n = k; n < src.length; n++) {
        if (src[n] === "{") d++;
        else if (src[n] === "}" && --d === 0) return src.slice(k, n + 1);
      }
      return null;
    }
    let d = 0;
    for (let n = m.index + m[0].length; n < src.length; n++) {
      const c = src[n];
      if (c === "{" || c === "(" || c === "[") d++;
      else if (c === "}" || c === ")" || c === "]") d--;
      else if (c === ";" && d <= 0) return src.slice(m.index + m[0].length, n);
    }
    return null;
  };
  const capteurs56 = [];
  for (const [f, src] of CORPUS_WEB) {
    if (!f.endsWith(".js")) continue;
    const re = /addEventListener\(\s*['"]scroll['"]\s*,\s*([A-Za-z_$][\w$]*)\s*,\s*true\s*\)/g;
    let m;
    while ((m = re.exec(src)) !== null) capteurs56.push([f, m[1], corpsDuGestionnaire56(src, m[1])]);
  }
  exiger(capteurs56.every(([, , corps]) => corps !== null),
    `(56b-instrument) le corps d'un gestionnaire de défilement n'a pas pu être délimité (${capteurs56.filter(([, , c]) => c === null).map(([f, n]) => f + ":" + n).join(", ")}) : cette jambe ne mesurerait rien, et se taire serait pire que rougir`);
  const sansGarde56 = capteurs56.filter(([, , c]) => c && !/\.contains\(/.test(c)).map(([f, n]) => `${f}:${n}`);
  exiger(sansGarde56.length === 0,
    `(56b) UN CAPTEUR DE DÉFILEMENT EN PHASE DE CAPTURE NE SE PROTÈGE PAS DE SON PROPRE POPOVER : ${sansGarde56.join(", ")}. En capture, le document reçoit AUSSI le défilement émis par la liste elle-même — elle se ferme au premier cran de molette, ce qui se lit exactement « elle ne défile pas »`);
  const inertes56 = capteurs56.filter(([, , c]) => c && !/close|fermer|masquer|remove/i.test(c)).map(([f, n]) => `${f}:${n}`);
  exiger(inertes56.length === 0,
    `(56b) UN CAPTEUR DE DÉFILEMENT NE FERME PLUS RIEN : ${inertes56.join(", ")}. Se protéger de son propre popover ne doit pas revenir à ne plus JAMAIS le fermer — le popover resterait ancré à une position périmée pendant que la page défile sous lui. C'est LE REMÈDE POUSSÉ TROP LOIN, et il doit rougir autrement que le défaut d'origine`);

  // — jambe C, BORNE MESURÉE : qui positionne encore un popover depuis un rectangle SANS le geste commun.
  const aLaMain56 = CORPUS_WEB
    .filter(([f, src]) => f.endsWith(".js") && f !== "core.js"
      && /style\.top\s*=\s*[^;]*\b\w*\.bottom/.test(src)
      && !/bornerLePopoverSousSonAncre/.test(src))
    .map(([f]) => f).sort();
  exiger(JSON.stringify(aLaMain56) === JSON.stringify(["app.js", "soql_complete.js"]),
    `(56-borne) les modules qui positionnent un popover depuis un rectangle SANS le geste commun ont changé : ${JSON.stringify(aLaMain56)} au lieu des DEUX MESURÉS SAINS le 2026-08-30. Ils le sont pour deux raisons STRUCTURELLES DIFFÉRENTES, et c'est pourquoi cette borne ne doit PAS tendre vers zéro : l'un ancre sa complétion dans un en-tête collant, si bien que le bas de son ancre ne descend jamais et que son contenu est plafonné ; l'autre pose sa boîte en coordonnées de PAGE, où la queue reste atteignable au défilement. Un module de PLUS est une régression. Un module de MOINS ne peut être qu'un ralliement DÉLIBÉRÉ — et rallier l'un de ces deux-là FERMERAIT UNE FAUSSE ACCUSATION pour le premier et DÉPLACERAIT le second de la hauteur de défilement exactement, le geste commun écrivant une position de FENÊTRE. Dans les deux cas cette borne se remesure et se réécrit, elle n'exige pas qu'un défaut subsiste.`);


  console.log(`[popover-dans-l-ecran] le geste commun de bornage tient la boîte DANS l'écran pour une ancre en haut, au milieu et en bas — hauteur en pixels RÉELS sous l'ancre, débordement rendu, bascule au-dessus quand l'espace manque —, et aucun capteur de défilement en phase de capture ne ferme sa propre liste ni ne cesse de fermer quoi que ce soit. CE QUE CE TÉMOIN NE TIENT PAS : il lit ce que le module POSE, jamais l'encre peinte ; il juge la BOÎTE et jamais son CONTENU ; il ne rejoue aucun redimensionnement de fenêtre ; et ${aLaMain56.length} module(s) positionnent encore un popover à la main (${aLaMain56.join(", ")}) — les deux MESURÉS SAINS le 2026-08-30, chacun pour une raison qui lui est propre et qu'un ralliement DÉFERAIT.`);
}

// ---------------------------------------------------------------------------------------------
// 57. UN SOUS-COMPTE PORTE SA MARQUE LÀ OÙ LE NOMBRE SE LIT — LA CELLULE, ET LE COMPTE DE LA
//     RANGÉE ; ET LE REFUS PARLE LA LANGUE DE SA VOISINE (`P11.21-j`).
//
//     POURQUOI CE TÉMOIN EXISTE, ET IL NE DOUBLE PAS LE 55. Le 55 tient l'AVEU DE PAGE : un corps
//     « lignes + cause » n'est plus rendu comme un refus, et l'aveu OUVRE le rendu. Il ne dit RIEN de
//     ce qui se lit plus bas. Un lecteur qui survole une cellule de la matrice sans avoir lu ce
//     bandeau lit `1r/0a` comme un COMPTE : le défaut fermé à l'échelle de la PAGE restait ouvert à
//     celle de la CELLULE, sur la surface même où un chiffre trop bas se lit « angle mort de
//     détection ». Même chose pour le total de la rangée de fraîcheur, qui se présente comme une
//     POPULATION alors qu'il compte les flux LUS.
//
//     L'INSTRUMENT SE VALIDE SUR LE DÉMON, ET C'EST CE QUI EMPÊCHE UN VERT PAR CONSTRUCTION. Ce que
//     la marque de cellule affirme — un MINORANT sur les alertes, une COUVERTURE qui n'en dépend pas —
//     est LU dans la cause servie par la route. Le jour où le démon cesse de séparer les deux, marquer
//     la seule alerte devient un choix sans fondement : ce témoin rougit et demande sa mise à jour.
//
//     ET LES DEUX MARQUES DOIVENT ÊTRE CONDITIONNELLES : le chemin NOMINAL est exercé le premier, et
//     une marque qui s'y rendrait est un ÉCHEC — une cellule qui avoue toujours n'avoue rien.
//
//     LA LANGUE SE MESURE PAR DIFFÉRENCE, JAMAIS PAR UNE PHRASE RECOPIÉE : la même issue rendue par
//     les deux instances du graphe doit rendre DEUX textes. Le témoin d'instrument est l'aveu
//     PARTIEL, déjà bilingue : s'il rend deux fois le même texte, c'est l'instance qui n'a pas pris
//     la langue, et le verdict sur le refus ne voudrait rien dire.
//
//     CE QU'IL NE TIENT PAS : il juge le TEXTE d'un arbre, jamais l'encre peinte ni la POSITION
//     visuelle de la marque ; et il ne dit rien de la TEINTE DE FOND de la cellule, qui est dérivée
//     du même compte d'alertes et donc elle aussi sous-comptée — c'est nommé, ce n'est pas tenu.
// ---------------------------------------------------------------------------------------------
{
  const CAUSE_57 = "CAUSE-DE-TRONCATURE-FABRIQUÉE-PAR-CE-BANC-57 : aucune phrase du démon n'est citée ici";
  const SUFFIXE_57 = "?plume-lang=en"; // le crochet de résolution est posé par le témoin 10
  const srcAlertes57 = readFileSync(path.join(RACINE, "daemon", "src", "handlers", "alerts.rs"), "utf8");

  // — instrument : LA SÉPARATION QUE LA MARQUE EXPLOITE EST CELLE DU DÉMON, PAS UNE HYPOTHÈSE DU BANC.
  const causeAttack57 = (srcAlertes57.match(/CAUSE_COMPTES_D_ALERTES_NON_ETABLIS[^=]*=\s*"([\s\S]*?)";/) || [])[1] || "";
  exiger(/covered/.test(causeAttack57) && /rule_count/.test(causeAttack57) && /alerts/.test(causeAttack57),
    "(57-instrument) la cause servie par /api/coverage/attack ne sépare plus les COMPTES D'ALERTES de la COUVERTURE (`covered`, `rule_count`) : marquer le seul nombre d'alertes n'a plus de fondement, mettez ce témoin à jour au lieu de le laisser vert");

  const rendre57 = async (module, nomExport, selecteur, corps, suffixe = "") => {
    const hote = new Element("div"), leg = new Element("div");
    const qs = document.querySelector, fx = globalThis.fetch;
    document.querySelector = (s) => (s === selecteur ? hote : s === "#attack-legend" ? leg : qs(s));
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify(corps) });
    try { const m = await import(pathToFileURL(path.join(WEB, module)).href + suffixe); await m[nomExport](); }
    finally { document.querySelector = qs; globalThis.fetch = fx; }
    return hote;
  };

  // --- (a) LA MATRICE ATT&CK : la marque est sur le NOMBRE, et sur lui seul. ---
  const { motDuSousCompteDAlertes: mot57Cell } = await import(pathToFileURL(path.join(WEB, "attack.js")).href);
  const MOT_CELL_57 = mot57Cell();
  const TAC57 = { tactic: "discovery", rule_count: 1, covered: true, techniques: [
    { tid: "T1046", name: "Network Service Discovery", covered: true, rule_count: 1, alert_count: 0 },
    { tid: "T1018", name: "Remote System Discovery", covered: false, rule_count: 0, alert_count: 0 }] };
  const matEntiere57 = await rendre57("attack.js", "loadAttackMatrix", "#attack-body", { tactics: [TAC57], totals: {} });
  const matPartielle57 = await rendre57("attack.js", "loadAttackMatrix", "#attack-body", { tactics: [TAC57], totals: {}, error: CAUSE_57 });
  const matRefus57 = await rendre57("attack.js", "loadAttackMatrix", "#attack-body", { tactics: [], totals: {}, error: CAUSE_57 });
  const cellules57 = (n) => n.querySelectorAll(".attack-cell");
  const cnt57 = (c) => (c.querySelectorAll(".attack-cnt")[0] || { textContent: "" }).textContent;
  const titres57 = (n) => cellules57(n).map((c) => c.title || "").join("\n");

  exiger(cellules57(matEntiere57).length === 2 && cellules57(matPartielle57).length === 2,
    `(57a-instrument) la matrice ne rend pas ses deux techniques (${cellules57(matEntiere57).length} / ${cellules57(matPartielle57).length}) : ce témoin ne pourrait pas rougir`);
  exiger(MOT_CELL_57.length > 20 && !MOT_CELL_57.includes(CAUSE_57),
    `(57a-instrument) le mot de la cellule n'est pas dérivable du module (« ${MOT_CELL_57} »)`);

  // LE CHEMIN NOMINAL NE PORTE AUCUNE MARQUE — sans quoi la surface cesserait de distinguer une lecture
  // entière d'un préfixe, et l'avertissement ne voudrait plus rien dire.
  exiger(!matEntiere57.textContent.includes("≥") && !titres57(matEntiere57).includes(MOT_CELL_57),
    `(57a) LA CELLULE AVOUE SUR UNE LECTURE ENTIÈRE : un corps qui avoue toujours n'avoue rien. Rendu : « ${cnt57(cellules57(matEntiere57)[0])} »`);

  const couverte57 = cellules57(matPartielle57).find((c) => c.textContent.includes("T1046"));
  const aveugle57 = cellules57(matPartielle57).find((c) => c.textContent.includes("T1018"));
  exiger(couverte57 && /^1r\/≥0a$/.test(cnt57(couverte57)),
    `(57a) LA CELLULE D'UNE TECHNIQUE COUVERTE AFFICHE SON NOMBRE D'ALERTES SANS MARQUE LOCALE : « ${couverte57 ? cnt57(couverte57) : "(pas de cellule)"} » au lieu de « 1r/≥0a ». Seul le bandeau au-dessus avertit ; un lecteur qui survole cette case sans l'avoir lu prend un SOUS-COMPTE pour un COMPTE, sur la surface même où un chiffre trop bas se lit « angle mort de détection ». Et la marque ne doit toucher QUE le nombre d'alertes : le compte de règles reste établi.`);
  exiger(couverte57 && (couverte57.title || "").includes(MOT_CELL_57),
    `(57a) le survol de la cellule marquée ne dit pas POURQUOI le nombre porte un signe : « ${couverte57 && couverte57.title} »`);
  // TÉMOIN NÉGATIF — la marque ne se pose pas là où rien n'est sous-compté : une cellule d'angle mort ne
  // rend AUCUN nombre d'alertes, et la marquer accuserait la COUVERTURE, que le démon déclare établie.
  exiger(aveugle57 && !aveugle57.textContent.includes("≥") && !(aveugle57.title || "").includes(MOT_CELL_57),
    `(57a) témoin négatif : la marque s'est posée sur une cellule qui ne rend aucun nombre d'alertes — elle y accuse la couverture, que la cause servie déclare ÉTABLIE. Rendu : « ${aveugle57 && cnt57(aveugle57)} »`);
  // LE REFUS NE CHANGE PAS DE MAIN : aucune cellule, la cause nommée, et aucune marque de sous-compte.
  exiger(cellules57(matRefus57).length === 0 && matRefus57.textContent.includes(CAUSE_57) && !matRefus57.textContent.includes("≥"),
    "(57a) un REFUS ne rend plus zéro cellule avec sa cause, ou s'est mis à porter la marque d'un sous-compte qu'il n'a pas");

  // --- (b) LA RANGÉE DE FRAÎCHEUR : le total cesse de se présenter comme une population. ---
  const { renderFreshnessDetail: detail57, motDuComptePartielDesFlux: mot57Flux } =
    await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const MOT_FLUX_57 = mot57Flux();
  const FLUX57 = [{ name: "syslog", kind: "event", age_s: 30, last_seen: 1800000000, status: "frais" },
                  { name: "auditd", kind: "event", age_s: 40, last_seen: 1800000000, status: "frais" }];
  const frEntier57 = detail57({ feeds: FLUX57, pipeline_fresh: true });
  const frPartiel57 = detail57({ feeds: FLUX57, pipeline_fresh: true, error: CAUSE_57 });
  exiger(MOT_FLUX_57.length > 20 && !MOT_FLUX_57.includes(CAUSE_57),
    `(57b-instrument) le mot du compte n'est pas dérivable du module (« ${MOT_FLUX_57} »)`);
  exiger(!frEntier57.includes(MOT_FLUX_57),
    "(57b) LE CHEMIN NOMINAL PORTE LE MOT D'INCOMPLÉTUDE : une rangée qui avoue toujours n'avoue rien");
  exiger(frPartiel57.includes(MOT_FLUX_57),
    "(57b) LES PASTILLES DU RELEVÉ COMPTENT LES FLUX LUS ET SE PRÉSENTENT COMME UNE POPULATION : « N flux observé(s) » se lit comme un inventaire sur une vue dont l'objet est de savoir si la donnée arrive encore, et un total trop bas s'y lit « des sources se sont tues »");
  const iMot57 = frPartiel57.indexOf(MOT_FLUX_57), iSomme57 = frPartiel57.indexOf(">=<");
  exiger(iMot57 > -1 && iSomme57 > -1 && iMot57 < iSomme57,
    "(57b) le mot n'est pas COLLÉ au total : rejeté après les parts, il ne qualifie plus le nombre qu'un lecteur vient chercher");
  const pulseEntier57 = await rendre57("freshness.js", "renderFreshnessPulse", "#freshness .body", { feeds: FLUX57, pipeline_fresh: true });
  const pulsePartiel57 = await rendre57("freshness.js", "renderFreshnessPulse", "#freshness .body", { feeds: FLUX57, pipeline_fresh: true, error: CAUSE_57 });
  exiger(pulsePartiel57.innerHTML.includes(MOT_FLUX_57) && !pulseEntier57.innerHTML.includes(MOT_FLUX_57),
    "(57b) LE PULSE — la charge VIVE du registre, la surface la plus souvent tirée de ce lot — laisse son compte se présenter comme une population, ou l'avoue sur une lecture entière");

  // --- (c) LE REFUS DE LA COUVERTURE PARLE LA LANGUE DE SA VOISINE. ---
  const corpsRefus57 = { detections: [], error: CAUSE_57 };
  const corpsPartiel57 = { detections: [{ mitre: "T1059", count: 2, first_ts: 1800000000 }], error: CAUSE_57 };
  const covRefusFR = await rendre57("detection_admin.js", "renderCoverage", "#cov-body", corpsRefus57);
  const covRefusEN = await rendre57("detection_admin.js", "renderCoverage", "#cov-body", corpsRefus57, SUFFIXE_57);
  const covPartielFR = await rendre57("detection_admin.js", "renderCoverage", "#cov-body", corpsPartiel57);
  const covPartielEN = await rendre57("detection_admin.js", "renderCoverage", "#cov-body", corpsPartiel57, SUFFIXE_57);
  exiger(covRefusFR.innerHTML.includes(CAUSE_57) && covRefusEN.innerHTML.includes(CAUSE_57),
    "(57c-instrument) une des deux instances ne rend plus le refus avec sa cause : la comparaison de langue porterait sur du vide");
  exiger(covPartielFR.innerHTML !== covPartielEN.innerHTML,
    "(57c-instrument) l'aveu de lecture PARTIELLE — déjà bilingue par construction — rend le MÊME texte dans les deux instances : c'est la seconde instance du graphe qui n'a pas pris la langue, et le verdict sur le refus ne voudrait rien dire");
  exiger(covRefusFR.innerHTML !== covRefusEN.innerHTML,
    `(57c) LA PHRASE DE REFUS DE LA COUVERTURE EST FRANÇAISE SEULE : les deux instances rendent le même texte, et sous l'autre langue cette vue met DEUX REGISTRES dans le même écran — l'aveu de lecture partielle, juste à côté, est bilingue. C'est l'issue la plus grave qui reste sans traduction : la seule qui interdise toute conclusion. Rendu : « ${covRefusFR.innerHTML} »`);

  console.log(`[sous-compte-marque-la-ou-le-nombre-se-lit] la marque descend jusqu'au NOMBRE : une cellule de technique COUVERTE rend « ${cnt57(couverte57)} » sur un corps tronqué et « ${cnt57(cellules57(matEntiere57).find((c) => c.textContent.includes("T1046")))} » sur une lecture entière — le signe ne touche QUE le compte d'alertes, jamais le compte de règles ni l'état de couverture, que la cause servie déclare établis ; une cellule d'angle mort n'en porte aucun (témoin négatif) ; le total de la rangée de fraîcheur porte le mot d'incomplétude COLLÉ au nombre, sur le détail comme sur le pulse, et rien sur une lecture entière ; et le refus de la couverture par détections rend deux textes dans les deux instances du graphe, l'aveu partiel voisin servant de témoin d'instrument. CE QUE CE TÉMOIN NE TIENT PAS : l'encre peinte et la POSITION visuelle des marques, et la teinte de fond de la cellule — dérivée du même compte d'alertes, donc elle aussi sous-comptée, ce qui est nommé et non tenu.`);
}

// ---------------------------------------------------------------------------------------------
// 58. LA SUGGESTION ACTIVE DE LA COMPLÉTION EST TOUJOURS DANS LE CHAMP DE VUE (`P11.22-c`).
//
//     MÊME FAMILLE QUE LE 56, UN CRAN PLUS HAUT, ET C'EST POURQUOI IL NE LE DOUBLE PAS. Le 56 tient la
//     BOÎTE : où elle est posée, et qu'elle tienne dans l'écran. Il le dit lui-même — « il juge la BOÎTE
//     et jamais son CONTENU ». Celui-ci ne juge QUE le contenu : la boîte de la complétion est
//     atteignable (elle est posée en coordonnées de PAGE, et c'est la raison pour laquelle la borne du
//     56 la déclare SAINE), sa queue défile, mais la SÉLECTION n'y allait pas.
//
//     MESURÉ le 2026-08-30, avant tout correctif : `filterItems` borne l'affichage à 40 suggestions ;
//     `.soql-ac` plafonne à 280 px, où tiennent 4 lignes portant leur doc sur deux lignes et 8 sans doc ;
//     `render()` reconstruit son contenu — le document borne alors le défilement à zéro — et il est
//     rappelé par CHAQUE flèche, pas seulement par chaque frappe ; et AUCUN geste de mise en vue
//     n'existait dans le module. Douze flèches vers le bas laissaient le défilement à 0 : la ligne
//     surlignée était hors du champ, sans erreur et sans qu'un mot le dise.
//
//     CE TÉMOIN SERAIT VERT PAR CONSTRUCTION S'IL N'ÉTAIT PAS INSTRUMENTÉ, ET LE LOT QUI A NOMMÉ LA CLÉ
//     L'AVAIT DIT. Avant le correctif le défilement vaut zéro QUOI QU'IL ARRIVE : un témoin qui lirait
//     seulement « le défilement vaut ce qu'il doit valoir » sans jamais prouver qu'il PEUT valoir autre
//     chose tiendrait une propriété vide. D'où trois précautions, et aucune n'est décorative :
//     (1) LA BOÎTE PEUT ENCORE DÉFILER — lu dans la feuille de style, pas supposé. Le jour où la borne
//         de hauteur ou le débordement disparaissent de `.soql-ac`, « garder la sélection en vue » ne
//         veut plus rien dire : ce témoin ROUGIT au lieu de rester vert sur du vide.
//     (2) LA LISTE DÉBORDE VRAIMENT — le nombre de lignes RENDUES par le module est comparé au nombre
//         qui tient dans la boîte. Une liste qui tiendrait entière ne pourrait rien prouver.
//     (3) LA MESURE FABRIQUÉE EST CONSOMMÉE — la section 0 déclare que le simulacre ne tient PAS la mise
//         en page ; ce témoin la POSE donc lui-même, et il vérifie dans les deux sens qu'elle est bien
//         lue : géométrie retirée, plus une seule écriture de défilement.
//
//     ET LE REMÈDE POUSSÉ TROP LOIN EST ATTRAPÉ SÉPARÉMENT. Un défilement qui sauterait à chaque cran,
//     ou qui ramènerait l'exploitant en haut sans qu'il le demande, serait PIRE que l'immobilité qu'on
//     corrige : la jambe (58b) exige ZÉRO écriture tant que la sélection reste visible, et la jambe
//     (58c) exige que remonter d'un cran sur une ligne DÉJÀ visible ne déplace RIEN — ce que seule la
//     reprise du défilement au travers de la reconstruction rend possible.
//
//     CE QU'IL NE TIENT PAS : il lit ce que le module POSE sur un simulacre dont IL fournit la
//     géométrie — jamais l'encre peinte, jamais la hauteur qu'un moteur de rendu donnerait vraiment à
//     une ligne. Il ne juge pas la POSITION de la boîte (c'est le 56). Il ne rejoue ni molette, ni
//     glissement de barre, ni redimensionnement. Et il ne dit rien de la borne de quarante suggestions :
//     elle est hors de son objet.
// ---------------------------------------------------------------------------------------------
{
  const mod58 = await import(pathToFileURL(path.join(WEB, "soql_complete.js")).href);
  const { primeCompletionMeta, initSoqlComplete, defilementQuiGardeLaSuggestionEnVue: enVue58 } = mod58;

  // — instrument (1) : LA BOÎTE PEUT ENCORE DÉFILER. Lu dans la feuille de style servie, pas supposé.
  const css58 = (CORPUS_WEB.find(([f]) => f === "style.css") || [, ""])[1];
  const bloc58 = (css58.match(/\.soql-ac\{[^}]*\}/) || [""])[0];
  const plafond58 = Number((bloc58.match(/max-height:\s*(\d+)px/) || [, 0])[1]);
  exiger(plafond58 > 0 && /overflow-y:\s*auto/.test(bloc58),
    `(58-instrument) la boîte de complétion n'est plus une région qui défile — \`.soql-ac\` rend « ${bloc58 || "(bloc introuvable)"} » : sans borne de hauteur NI débordement, « garder la sélection en vue » ne tient plus rien, et rester vert dirait le contraire`);
  exiger(typeof enVue58 === "function",
    "(58-instrument) la décision de mise en vue a disparu de soql_complete.js : ce témoin n'a plus d'objet, mettez-le à jour au lieu de le laisser vert");

  // Hauteur UTILE : le plafond lu, moins la bordure (1px × 2) et le remplissage (4px × 2) du même bloc.
  // Hauteur de LIGNE : celle d'une suggestion portant sa doc sur ses deux lignes (5+5 de remplissage,
  // 21 de libellé à .92rem/1.55, 1 d'espacement, 2 × 14 de description à .76rem/1.25) — MESURÉE dans la
  // feuille le 2026-08-30. Ce sont des nombres FABRIQUÉS : ils ne prétendent pas à l'encre peinte, ils
  // donnent au simulacre une géométrie COHÉRENTE que le code doit consommer correctement.
  const VUE58 = plafond58 - 10, LIGNE58 = 61;
  const TIENNENT58 = Math.floor(VUE58 / LIGNE58);
  exiger(TIENNENT58 >= 2 && TIENNENT58 <= 12,
    `(58-instrument) ${TIENNENT58} ligne(s) tiendraient dans la boîte : hors de toute plage plausible, la géométrie fabriquée ne modélise plus rien`);

  // — le simulacre ne tient PAS la mise en page (section 0) : ce témoin la POSE, et la RETIRE ensuite.
  let geometrie58 = true;
  const poser58 = (nom, lire) => Object.defineProperty(Element.prototype, nom, { configurable: true, get: lire });
  poser58("offsetHeight", function () { return geometrie58 && this._classes.has("soql-ac-item") ? LIGNE58 : 0; });
  poser58("offsetTop", function () { const p = this.parentNode; return geometrie58 && p ? p.children.indexOf(this) * LIGNE58 : 0; });
  poser58("clientHeight", function () { return geometrie58 && this._classes.has("soql-ac") ? VUE58 : 0; });

  class Editeur58 extends Element {
    constructor() { super("textarea"); this.selectionStart = 0; this.selectionEnd = 0; this._ec = {}; }
    addEventListener(t, f) { (this._ec[t] = this._ec[t] || []).push(f); }
    dispatchEvent(ev) { (this._ec[ev.type] || []).forEach((f) => f(ev)); return true; }
    setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
  }
  // Un vocabulaire assez large pour que la liste DÉBORDE : c'est la condition de la mesure, et elle est
  // vérifiée plus bas sur le nombre de lignes RENDUES, jamais supposée depuis ce jeu.
  const champs58 = Array.from({ length: 30 }, (_, i) => `champ_${String(i).padStart(2, "0")}`);
  primeCompletionMeta({
    base_keywords: ["search", "metric"], commands: ["where", "stats", "sort"],
    stats_functions: ["count"], eval_functions: ["if"], operators: ["=", "!=", ">", "<"],
    fields: { core: champs58, extended: [] },
    values: {}, docs: { fields: Object.fromEntries(champs58.map((c) => [c, "description curée sur deux lignes de " + c])) },
  }, []);

  const ed58 = new Editeur58();
  const parId58 = document.getElementById;
  document.getElementById = (id) => (id === "sql" ? ed58 : new Element("div"));
  initSoqlComplete();
  document.getElementById = parId58;
  exiger(ed58.dataset.acWired === "1", "(58-instrument) l'éditeur fabriqué n'a pas été câblé : rien de ce qui suit ne mesurerait le module");

  const frapper58 = (t) => { ed58.value = t; ed58.setSelectionRange(t.length, t.length); ed58.dispatchEvent({ type: "input" }); };
  const fleche58 = (key) => ed58.dispatchEvent({ type: "keydown", key, ctrlKey: false, metaKey: false, preventDefault() {} });
  const pause58 = () => new Promise((r) => setTimeout(r, 0));
  frapper58("search ");
  await pause58();
  const boite58 = document.body.children.find((c) => c.classList.contains("soql-ac"));
  exiger(!!boite58 && !boite58.hidden, "(58-instrument) la boîte de complétion n'a pas été rendue : le témoin n'a rien à mesurer");

  // Le défilement est un ACCESSEUR : on compte les écritures du module, et on modélise la seule chose que
  // le document réel fait de son côté — BORNER LE DÉFILEMENT À ZÉRO quand le contenu disparaît. Sans cette
  // moitié, la reprise du défilement au travers de la reconstruction serait un no-op ici, et la jambe
  // (58c) serait VERTE PAR CONSTRUCTION : elle ne distinguerait pas un module qui reprend son défilement
  // d'un module qui repart du haut à chaque cran.
  let defilement58 = 0, ecritures58 = 0;
  const htmlOrigine58 = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
  Object.defineProperty(boite58, "scrollTop", { configurable: true, get: () => defilement58, set: (v) => { defilement58 = v; ecritures58++; } });
  Object.defineProperty(boite58, "innerHTML", {
    configurable: true,
    get() { return htmlOrigine58.get.call(this); },
    set(v) { htmlOrigine58.set.call(this, v); defilement58 = 0; },   // le DOCUMENT, pas le module : non compté
  });

  // — instrument (2) : la liste DÉBORDE vraiment de la boîte, sinon rien ne se prouverait.
  frapper58("search ");
  await pause58();
  const rendues58 = boite58.children.length;
  exiger(rendues58 > TIENNENT58 + 6,
    `(58-instrument) la liste rend ${rendues58} ligne(s) pour ${TIENNENT58} visible(s) : elle ne déborde pas assez pour que « hors du champ » veuille dire quelque chose`);

  // — instrument (3) : la géométrie fabriquée est-elle CONSOMMÉE ? Sans elle, plus une seule écriture.
  geometrie58 = false;
  defilement58 = 0; ecritures58 = 0;
  for (let i = 0; i < 12; i++) fleche58("ArrowDown");
  exiger(ecritures58 === 0,
    `(58-instrument) géométrie RETIRÉE, le module a tout de même écrit ${ecritures58} fois le défilement (valeur ${defilement58}) : il pose un défilement qu'il n'a pas mesuré, et les jambes suivantes liraient un nombre inventé`);
  geometrie58 = true;

  // — jambe (58a), EXÉCUTÉE : douze flèches vers le bas, et la ligne active est DANS le champ.
  frapper58("search ");
  await pause58();
  defilement58 = 0; ecritures58 = 0;
  const CIBLE58 = 12;
  for (let i = 0; i < CIBLE58; i++) fleche58("ArrowDown");
  const active58 = boite58.children.findIndex((r) => r._classes.has("active"));
  exiger(active58 === CIBLE58,
    `(58a-instrument) après ${CIBLE58} flèches la ligne surlignée est la n°${active58} : la navigation au clavier ne fait plus ce que ce témoin croit mesurer`);
  const hautDeLaLigne58 = active58 * LIGNE58, basDeLaLigne58 = hautDeLaLigne58 + LIGNE58;
  exiger(hautDeLaLigne58 >= defilement58 && basDeLaLigne58 <= defilement58 + VUE58,
    `(58a) LA COMPLÉTION SURLIGNE UNE SUGGESTION QUE PERSONNE NE VOIT : après ${CIBLE58} flèches vers le bas, la ligne n°${active58} occupe ${hautDeLaLigne58}..${basDeLaLigne58}px pendant que la boîte montre ${defilement58}..${defilement58 + VUE58}px. La boîte défile — c'est la SÉLECTION qui n'y va pas, et rien à l'écran ne dit qu'il y a plus bas`);
  exiger(defilement58 === basDeLaLigne58 - VUE58,
    `(58a) la ligne sortie par le BAS n'est pas alignée sur le bord par lequel elle est sortie : défilement ${defilement58} au lieu de ${basDeLaLigne58 - VUE58} — un alignement en haut, ou un recentrage, déplacerait la liste plus que nécessaire`);

  // — jambe (58b), TÉMOIN NÉGATIF : tant que la sélection reste visible, RIEN ne bouge.
  frapper58("search ");
  await pause58();
  defilement58 = 0; ecritures58 = 0;
  for (let i = 0; i < TIENNENT58 - 1; i++) fleche58("ArrowDown");
  exiger(ecritures58 === 0 && defilement58 === 0,
    `(58b) LE REMÈDE POUSSÉ TROP LOIN : la sélection est encore dans les ${TIENNENT58} premières lignes et le module a déjà écrit ${ecritures58} fois le défilement (valeur ${defilement58}). Une liste qui saute à chaque cran, ou qui se recentre sans qu'on le demande, est PIRE que celle qui ne bougeait pas`);

  // — jambe (58c), LA RECONSTRUCTION : remonter d'un cran sur une ligne DÉJÀ visible ne déplace RIEN.
  //   `render()` vide son contenu avant de le refaire, ce qui borne le défilement à zéro. Sans reprise,
  //   ce cran-là recalculerait depuis le haut et la liste sauterait — le défaut RETOURNÉ.
  frapper58("search ");
  await pause58();
  defilement58 = 0;
  for (let i = 0; i < CIBLE58; i++) fleche58("ArrowDown");
  const apresDescente58 = defilement58;
  ecritures58 = 0;
  fleche58("ArrowUp");
  const actifRemonte58 = boite58.children.findIndex((r) => r._classes.has("active"));
  exiger(actifRemonte58 === CIBLE58 - 1,
    `(58c-instrument) la flèche vers le haut n'a pas reculé d'un cran (ligne n°${actifRemonte58}) : cette jambe ne mesurerait pas ce qu'elle annonce`);
  exiger(defilement58 === apresDescente58,
    `(58c) LA LISTE SAUTE À LA RECONSTRUCTION : remonter d'un cran sur une ligne DÉJÀ visible a déplacé le défilement de ${apresDescente58} à ${defilement58}. Le rendu vide son contenu avant de le refaire — le document borne alors le défilement à zéro — et sans reprise de la valeur RELEVÉE avant le vidage, chaque cran repart du haut`);

  // — jambe (58d) : une FRAPPE remet la sélection en tête, et le champ de vue la suit.
  defilement58 = apresDescente58;
  frapper58("search c");
  await pause58();
  exiger(boite58.children.length > 0 && defilement58 === 0,
    `(58d) après une frappe, la suggestion active redevient la PREMIÈRE et le champ de vue est resté à ${defilement58} : l'exploitant lirait une fenêtre périmée pendant que la sélection est ailleurs`);

  // — la décision NUE, dans les deux sens : elle ne bouge que par le bord franchi, et elle refuse de
  //   conclure sur une géométrie qu'elle n'a pas. `null` est le cas NOMINAL.
  exiger(enVue58({ defilement: 100, hauteurVisible: 270 }, { haut: 120, hauteur: 61 }) === null,
    "(58e) la décision déplace une ligne DÉJÀ dans le champ : le cas nominal doit être l'immobilité");
  exiger(enVue58({ defilement: 100, hauteurVisible: 270 }, { haut: 40, hauteur: 61 }) === 40,
    "(58e) une ligne sortie par le HAUT n'est pas alignée sur le haut du champ");
  exiger(enVue58({ defilement: 0, hauteurVisible: 270 }, { haut: 305, hauteur: 61 }) === 96,
    "(58e) une ligne sortie par le BAS n'est pas alignée sur le bas du champ");
  exiger(enVue58({ defilement: 0, hauteurVisible: 0 }, { haut: 305, hauteur: 61 }) === null
      && enVue58({ defilement: 0, hauteurVisible: NaN }, { haut: 305, hauteur: 61 }) === null,
    "(58e) la décision conclut sur une géométrie ABSENTE : elle poserait un défilement dérivé d'un vide, ce qui ramènerait la liste en haut sans qu'on l'ait demandé");

  delete Element.prototype.offsetHeight; delete Element.prototype.offsetTop; delete Element.prototype.clientHeight;

  console.log(`[suggestion-active-en-vue] la complétion rend ${rendues58} suggestions dans une boîte où ${TIENNENT58} tiennent (plafond ${plafond58}px LU dans la feuille servie) : ${CIBLE58} flèches vers le bas laissent la ligne surlignée DANS le champ, alignée sur le seul bord qu'elle a franchi ; tant qu'elle reste visible le module n'écrit PAS UNE FOIS le défilement ; remonter d'un cran au travers d'une reconstruction ne déplace rien ; et une frappe qui remet la sélection en tête ramène le champ de vue avec elle. L'instrument est validé dans les deux sens : géométrie retirée, ZÉRO écriture — le nombre lu plus haut est donc bien MESURÉ et non inventé. CE QUE CE TÉMOIN NE TIENT PAS : la géométrie est FABRIQUÉE (la section 0 déclare que le simulacre ne tient pas la mise en page), donc il juge le code qui la consomme et jamais l'encre peinte ni la hauteur réelle d'une ligne ; il ne dit rien de la POSITION de la boîte, tenue par le témoin 56 ; il ne rejoue ni molette, ni glissement de barre, ni redimensionnement ; et la borne de quarante suggestions est hors de son objet.`);
}

// LE VERDICT PORTE SA PROPRE LIMITE (`P11.13-g`). Un vert qui ne dit pas ce sur quoi il ne s'engage pas
// se lit comme une COUVERTURE — et un rouge n'a pas plus le droit de laisser croire qu'il a tout regardé.
// La phrase ci-dessous n'est pas écrite : elle est DÉRIVÉE des sondes de la section 0, donc une capacité
// fermée en sort d'elle-même et une capacité qui régresse y entre sans que personne l'écrive.
const CE_QUE_CE_VERDICT_NE_DIT_PAS = `\n\nCE QUE CE VERDICT NE DIT PAS — dérivé du simulacre par ${CAPACITES.length} sondes validées dans les deux sens, jamais recopié :\n  · ${AVEU}`;
verdictRendu = true;
if (echecs.length) {
  for (const e of echecs) console.error(`::error::${e}`);
  console.error(`\n${echecs.length} témoin(s) en échec : la surface aplatit un verdict.${CE_QUE_CE_VERDICT_NE_DIT_PAS}`);
  process.exit(1);
}
console.log(`OK — ${modules.length} modules web se lient ; le panneau Système rend l'état « NON LISIBLE » avec sa cause sur 5 tuiles, les bilans de boucles et les grandeurs de composant, et la valeur quand le verdict est « lu » (vrai zéro compris) ; un playbook livré et un runbook créé rendent par la même fabrique de ligne, avec le mot de leur état et leur conséquence ; la liste des alertes rend une seule barre d'actions sur tous ses tris, aucune action n'est désactivée au motif d'une facette, et la facette source dit son objet et son étendue ; une technique ATT&CK sans nom se dit, l'éditeur de requête laisse « != » en place sous la frappe, la palette des modèles porte modifier/supprimer/copier, et le badge de troncature nomme le saut de page ; l'inventaire des sources NOMME le déclarant de chaque source — ce dépôt, le démon, le produit, un connecteur, ou l'exploitant avec sa date — dit « personne ne l'a déclarée » là où c'est le cas, et n'offre de déclarer une cadence que là où aucune sonde n'en déclare ; la fraîcheur rend le statut du démon (une périodique dans sa cadence = frais, jamais « dégradé ») et RÉPARTIT les alertes actives entre celles qu'une cloche porte, celles qui ne se rapportent à aucun flux (et qui pivotent vers elles-mêmes) et celles dont l'imputation n'a jamais été enregistrée, sans rien afficher quand aucune alerte n'est active ; une carte d'administration se replie par son bouton sans jamais le griser, un formulaire de création ne rend aucun bouton nu, et la confirmation partagée exige une conséquence nommée, bloque écartée et passe validée ; la sidebar porte deux espaces « Recherche » et « Cas » égaux au modèle de navigation, les alertes sous Cas, l'éditeur seul sous Recherche, chaque section mappée existe, et les deux familles de l'onglet Playbooks sont nommées dans leurs en-têtes et boutons, la durée du ban suivant la valeur servie ; les fabriques de bouton des cas et des producteurs, la barre des alertes et le bloc MFA ne rendent aucun bouton nu ni style en ligne, et chaque bouton d'aide a sa section ; l'aide « Jetons » s'ouvre et dit le secret montré une seule fois, et une clé sans section ouvre un aveu qui la nomme ; le bouton de fermeture des modales d'aide et les titres du guide rendent en anglais par le lexique, jamais par un mot écrit dans le module ; l'amorçage pose l'observateur du lexique sur le corps du document et celui-ci traduit un nœud texte, un élément et un attribut posés après coup ; le panneau d'accès données rend cinq cartes qui DISTINGUENT un refus du démon d'une absence de données — sans réseau elles avouent leur cause au lieu d'affirmer un vide — son sélecteur et ses sept chemins surveillés ; la ligne d'un lookup porte nom, badge, clé, colonnes et bouton habillé, et le collage CSV lit les guillemets et refuse un collage sans données ; une tuile de dashboard rend son titre, ses outils selon le droit, sa largeur, et sa grille avoue l'erreur sans réseau ; l'encart d'identité nomme la méthode d'authentification hors session cookie et l'écran de connexion verrouille le corps du document en coupant l'auto-rafraîchissement ; un onglet interdit, inconnu ou renommé se replie sur la vue d'ensemble sans réécrire le lien profond ; la ligne d'un cas ouvre et REFERME le détail par le dépli partagé, le bouton du détail emprunte le même chemin et repeint la ligne, un cas terminé rend un statut inerte qui NOMME sa raison et sa sortie là où il n'en rendait aucun, un cas en cours ne la porte pas, et un droit manquant se dit autrement qu'un état qui ne bouge plus ; la ligne d'une règle rend DÉJÀ tester, éditer, supprimer et un interrupteur actif pour un administrateur, inerte et motivé pour un lecteur ; et LA recherche de liste, partagée, resserre sur plusieurs mots sans se soucier de la casse ni des accents, cherche une règle par son nom, sa requête et sa technique, rend une liste plate ordonnée par le tri courant qui DIT combien de lignes sur combien elle montre, nomme ce qu'elle a cherché quand elle ne trouve rien, et se vide au retour d'un enregistrement pour que la règle écrite se voie ; enfin une technique ATT&CK est une PORTE — ses règles, ses détections par le pivot qui existait déjà (le module ne fabrique aucune requête) et le geste qui la couvrirait, un angle mort qui se dit et met la création en avant, une sortie impraticable rendue inerte avec son motif, et un lecteur à qui le rôle manquant est nommé ; un filtre choisi de la barre des alertes ne se marque plus par la graisse de son mot — que le gras réservait ailleurs à l'alarme — mais par un liseré que rien d'autre n'emploie, et il DIT son état ; l'espace qui porte les alertes et les cas les annonce tous les deux — aucun espace à plusieurs onglets ne porte plus le nom d'un seul — et son filtre se nomme par ce qu'il MONTRE au lieu d'une relation que l'exploitant ne savait pas lire ; une alerte se cherche par son titre, le jeton de sa regle et sa source imputee, par LE meme champ partage : la recherche se compose avec la portee, le filtre d'affichage et les facettes sans jamais partir au demon, met le groupement de cote le temps de rendre ses resultats, DIT ce qu'elle couvre — les alertes servies, ou la seule page affichee — et retire de la barre l'acquittement qui la depasserait ; la selection rend ce qui est selectionne — le clic d'une ligne de resultats et celui d'un titre d'alerte se retirent devant une selection faite chez eux, et devant elle seule — pendant qu'UN unique geste de copie, seul ecrivain du presse-papier dans web/, accuse le succes et avoue un refus au lieu de le taire ; le detail d'un composant du panneau Systeme n'est plus coupe a une ligne par la feuille de style — l'avertissement d'exercice de restauration se lit jusqu'a sa conclusion et la reference documentaire qu'il porte se copie en un geste, faute d'etre servie par une route ; et les trois correctifs que rien ne tenait le sont enfin : un refus de lire l'inventaire de flotte ou la couverture ATT&CK ne se rend NI en panne d'ingestion constatée NI en absence établie — les trois issues sont distinctes sur la même fonction, et les deux phrases qu'un refus ne doit pas reprendre sont dérivées du rendu, jamais recopiées ; le bouton qui efface les dates n'est offert que lorsqu'il a quelque chose à retirer, sur quatre états et jusque sur le retrait fait par une AUTRE vue, qui passe par l'écrivain unique de la plage ; et les deux derniers déplis écrits à la main NOMMENT la région qu'ils commandent, ce qu'aucun d'eux ne faisait, la borne disant combien de modules ne sont pas ralliés. ENFIN une page INCOMPLÈTE n'est plus rendue comme un REFUS sur les trois vues qui jetaient ce qu'elles avaient reçu : une matrice ATT&CK, une couverture de détections et un relevé de fraîcheur servis AVEC des lignes ET une cause rendent leurs lignes SOUS un aveu qui ouvre le rendu, le chemin nominal n'en porte aucun, et les trois voies d'aveu sont LUES dans l'arbre du démon — si l'une cesse d'exister, ce témoin REFUSE DE CONCLURE au lieu de rester vert sur une propriété devenue vide.${CE_QUE_CE_VERDICT_NE_DIT_PAS}`);

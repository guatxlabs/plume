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
// c'est le TEXTE de cet arbre qui est jugé. `fetch` est absent par construction — une surface qui
// appellerait le réseau au chargement d'un module est une erreur, et elle se voit ici.
import { readdirSync } from "node:fs";
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
    this.children = [];
    this.parentNode = null;
    this.attributes = {};
    this.style = {};
    this.dataset = {};
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
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { this._text = String(v ?? ""); this.children = []; }
  get innerHTML() { return this._html ?? ""; }
  set innerHTML(v) { this._html = String(v); this.children = []; this._text = ""; }
  get innerText() { return this.textContent; }
  set innerText(v) { this.textContent = v; }
  get firstChild() { return this.children[0] ?? null; }
  get lastChild() { return this.children[this.children.length - 1] ?? null; }
  get childNodes() { return this.children; }
  get isConnected() { return true; }
  appendChild(c) { if (c instanceof Fragment) { c.children.forEach((x) => this.appendChild(x)); return c; } c.parentNode = this; this.children.push(c); return c; }
  append(...cs) { cs.forEach((c) => this.appendChild(typeof c === "string" ? document.createTextNode(c) : c)); }
  prepend(...cs) { cs.reverse().forEach((c) => { const n = typeof c === "string" ? document.createTextNode(c) : c; n.parentNode = this; this.children.unshift(n); }); }
  replaceChildren(...cs) { this.children = []; this._text = ""; this.append(...cs); }
  insertBefore(n, ref) { const i = this.children.indexOf(ref); n.parentNode = this; if (i < 0) this.children.push(n); else this.children.splice(i, 0, n); return n; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); return c; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  replaceWith(...cs) { if (!this.parentNode) return; const p = this.parentNode, i = p.children.indexOf(this); p.children.splice(i, 1, ...cs); cs.forEach((c) => (c.parentNode = p)); }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  removeAttribute(k) { delete this.attributes[k]; }
  hasAttribute(k) { return k in this.attributes; }
  addEventListener() {}
  removeEventListener() {}
  dispatchEvent() { return true; }
  focus() {} blur() {} click() {} scrollIntoView() {} select() {}
  closest() { return null; }
  contains(n) { return n === this || this.children.some((c) => c.contains && c.contains(n)); }
  getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0, right: 0, bottom: 0 }; }
  querySelector() { return new Element("div"); }
  querySelectorAll() { return []; }
  getContext() { return null; }
  cloneNode() { const e = new Element(this.tagName); e.className = this.className; e._text = this._text; return e; }
}
class Text { constructor(t) { this._t = String(t); this.parentNode = null; } get textContent() { return this._t; } set textContent(v) { this._t = String(v); } contains() { return false; } }
class Fragment extends Element { constructor() { super("#fragment"); } }

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
  addEventListener() {}, removeEventListener() {},
  execCommand: () => false,
};
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
  MutationObserver: class { observe() {} disconnect() {} },
  ResizeObserver: class { observe() {} disconnect() {} unobserve() {} },
  IntersectionObserver: class { observe() {} disconnect() {} unobserve() {} },
  EventSource: class { constructor() { this.readyState = 0; } close() {} addEventListener() {} },
  WebSocket: class { constructor() { this.readyState = 0; } close() {} addEventListener() {} send() {} },
  // Réseau : absent par construction. Un appel au chargement d'un module est une faute, et elle se voit.
  fetch: undefined,
};
for (const [k, v] of Object.entries(fenetre)) Object.defineProperty(globalThis, k, { value: v, writable: true, configurable: true });
globalThis.window = globalThis;
globalThis.self = globalThis;

// Le texte d'un sous-arbre, tel qu'un lecteur le verrait (sans mise en page).
const texte = (el) => el.textContent;

// ---------------------------------------------------------------------------------------------
// 1. LE GRAPHE DE MODULES SE LIE — chaque module suivi de `web/`, sauf le service worker (il n'est
//    pas un module ES et lit des globales de son propre contexte).
// ---------------------------------------------------------------------------------------------
const modules = readdirSync(WEB).filter((f) => f.endsWith(".js") && f !== "sw.js").sort();
const liens = [];
for (const f of modules) {
  try {
    await import(pathToFileURL(path.join(WEB, f)).href);
  } catch (e) {
    liens.push(`${f} : ${e && e.name} — ${e && e.message}`);
  }
}
if (liens.length) {
  for (const l of liens) console.error(`::error::module web qui ne se charge pas : ${l}`);
  console.error(`\n${liens.length} module(s) sur ${modules.length} ne se chargent pas : l'interface serait VIDE.`);
  process.exit(1);
}
const PLANCHER_MODULES = 20;
if (modules.length < PLANCHER_MODULES) {
  console.error(`::error::seulement ${modules.length} modules découverts sous web/, plancher ${PLANCHER_MODULES} : la découverte est cassée, le harnais refuse de conclure.`);
  process.exit(2);
}

// ---------------------------------------------------------------------------------------------
// 2. LE VERDICT EST RENDU — panneau Système sur des objets fabriqués.
// ---------------------------------------------------------------------------------------------
const { rendreSysteme, lireMesure } = await import(pathToFileURL(path.join(WEB, "system.js")).href);
const echecs = [];
const exiger = (cond, msg) => { if (!cond) echecs.push(msg); };

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

if (echecs.length) {
  for (const e of echecs) console.error(`::error::${e}`);
  console.error(`\n${echecs.length} témoin(s) en échec : la surface aplatit un verdict.`);
  process.exit(1);
}
console.log(`OK — ${modules.length} modules web se lient ; le panneau Système rend l'état « NON LISIBLE » avec sa cause sur 5 tuiles, les bilans de boucles et les grandeurs de composant, et la valeur quand le verdict est « lu » (vrai zéro compris).`);

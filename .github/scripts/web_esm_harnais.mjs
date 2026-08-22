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
// Relevé ICI, avant toute instance sous `LANG='en'` : ce que la liaison française a posé sur le corps du document.
const observateursSurLeCorpsApresLiaison = observateursPoses.filter((o) => o.cible === document.body).length;
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
  // « Sans règle CSS » est DÉRIVÉ de style.css (P11.4-b : les boutons de ligne portent `btn btn-sm`) ; `crud-btn` et
  // `mg-nodel` sont des classes d'état (masquage au viewer, pas de suppression), sans chrome, nommées ici.
  const css = readFileSync(path.join(WEB, "style.css"), "utf8");
  const aRegle = (k) => k === "crud-btn" || k === "mg-nodel" || new RegExp("\\." + k + "(?![\\w-])").test(css);
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
  exiger(/class="agseg on" data-g="rule" title=/.test(sourceGroupee) && /class="agscope on" data-act="scope" title=/.test(sourceGroupee), `(4) sous la facette source, le tri « Règle » et la portée « tous statuts » doivent être actifs, sans \`disabled\` : ${sourceGroupee.match(/<button[^>]*data-g="rule"[^>]*>/)?.[0]} ${sourceGroupee.match(/<button[^>]*data-act="scope"[^>]*>/)?.[0]}`);
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
//    (a) Une technique sans nom se DIT : « nom inconnu », jamais une cellule vide ; une sous-technique
//        que le démon n'a pas nommée se résout par son parent côté client.
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
  // sous-technique sans nom servi -> résolue par le parent via la table locale
  exiger(techniqueDisplayName({ tid: "T1110.003" }) === "Brute Force", `(4a) sous-technique non nommée par le démon : « ${techniqueDisplayName({ tid: "T1110.003" })} » au lieu du parent`);
  exiger(techniqueDisplayName({ tid: "T1110", name: "   " }) === "Brute Force", "(4a) un nom vide servi doit compter comme absent");
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
      // livrée par ce dépôt : attendue par construction, la raison nomme le fichier ; calme sans cadence déclarée.
      { source: "portprobe", expected: true, unexpected: false, in_collectors: true, raison_attendue: "émise par un fichier livré (collectors/portprobe.sh)", marquage: null, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 72, last_seen: 1000, age_s: 7200, n_24h: 1200, status: "calme" },
      // rien ne la déclare, personne ne l'a marquée : le signal.
      { source: "derive-deploiement", expected: false, unexpected: true, in_collectors: false, raison_attendue: null, marquage: null, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 3600, last_seen: 1000, age_s: 3000, n_24h: 24, status: "calme" },
      // marquée attendue par un éditeur : qui et quand sont rendus.
      { source: "vault-custom", expected: true, unexpected: false, in_collectors: false, raison_attendue: "marquée attendue par eve (ts 1700000000)", marquage: { expected: true, updated_by: "eve", updated: 1700000000 }, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 600, last_seen: 1000, age_s: 120, n_24h: 144, status: "frais" },
      // continue déclarée et dépassée : en retard, avec la cadence et la sonde.
      { source: "auditd", expected: true, unexpected: false, in_collectors: true, raison_attendue: "émise par un fichier livré (collectors/auditd.sh)", marquage: null, cadence_declaree: "continue", cadence_interval_s: 120, cadence_capteur: "audit", observed_interval_s: 30, last_seen: 1000, age_s: 1200, n_24h: 2880, status: "en_retard" },
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
  exiger(lPort && !celluleTexte(lPort, 0).includes("inattendu"), "(inventaire) une source LIVRÉE porte le badge « inattendu » : la dérivation n'est pas lue");
  exiger(lPort && texte(lPort).includes("collectors/portprobe.sh"), `(inventaire) la raison « attendue par construction » (fichier livré) n'est pas rendue : « ${lPort && texte(lPort)} »`);
  exiger(lDer && celluleTexte(lDer, 0).includes("inattendu"), "(inventaire) une source que rien ne déclare ne porte PAS le badge « inattendu »");
  exiger(lDer && celluleTexte(lDer, 1).includes("non déclarée"), `(inventaire) le « non » d'une source inattendue n'est pas expliqué : « ${lDer && celluleTexte(lDer, 1)} »`);
  exiger(lVc && !celluleTexte(lVc, 0).includes("inattendu") && texte(lVc).includes("marquée attendue par eve"), `(inventaire) le marquage (qui) n'est pas rendu : « ${lVc && texte(lVc)} »`);
  exiger(lAud && texte(lAud).includes("en retard") && texte(lAud).includes("continu · 2 min"), `(inventaire) « en retard » et la cadence déclarée ne sont pas rendus : « ${lAud && texte(lAud)} »`);
  exiger(lPort && texte(lPort).includes("calme") && !texte(lPort).includes("retard") && texte(lPort).includes("non déclarée"), `(inventaire) une source sans cadence déclarée, silencieuse 2 h, doit lire « calme » et « non déclarée » : « ${lPort && texte(lPort)} »`);
  exiger(texte(invA).includes("1 source(s) que rien ne déclare"), "(inventaire) le compte des signaux n'est pas rendu en tête");
  exiger(!texte(invA).includes("dégradé"), "(inventaire) le mot « dégradé » survit dans l'inventaire");
  // (b) ÉDITEUR : la colonne Actions existe et offre « marquer attendue » sur le signal, « marquer inattendue » sur l'acquittée.
  document.body.className = "role-editor";
  const invB = new Element("div");
  renderSourcesInventory(invB, inventaire);
  const colsB = enTetes(invB);
  exiger(colsB.includes("Actions"), `(inventaire, editor) aucune colonne Actions : l'éditeur n'a toujours aucune issue (${colsB.join(", ")})`);
  const lignesB = lignesDe(invB);
  const actionsDe = (tr) => { const td = tr.children[tr.children.length - 1]; const out = []; const marcher = (el) => { if (!el || !el.children) return; if (el.tagName === "BUTTON") out.push(texte(el)); el.children.forEach(marcher); }; marcher(td); return out; };
  exiger(actionsDe(ligne(lignesB, "derive-deploiement")).includes("marquer attendue"), `(inventaire, editor) le signal n'offre pas « marquer attendue » : ${JSON.stringify(actionsDe(ligne(lignesB, "derive-deploiement")))}`);
  exiger(actionsDe(ligne(lignesB, "vault-custom")).includes("marquer inattendue"), "(inventaire, editor) une source marquée n'offre pas le geste inverse (réversibilité)");
  exiger(texte(invB).includes("Actions → « marquer attendue »"), "(inventaire, editor) l'en-tête ne dit pas à l'éditeur où est le geste");
  document.body.className = "";
}

// ---------------------------------------------------------------------------------------------
// 6. LA FRAÎCHEUR (`P11.3-b`) — le statut vient du démon ; une périodique dans sa cadence est « frais »
//    ou « calme », jamais « en retard » ; « dégradé » n'existe plus ; les alertes sont un compte.
// ---------------------------------------------------------------------------------------------
{
  const { renderFreshnessDetail, freshState, countStates } = await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const feeds = {
    pipeline_fresh: true, unattributed_alerts: 0, feeds: [
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
  exiger(/mail cadence non déclarée/.test(brut) && /yara événementiel/.test(brut) && /kube-audit continu · 2 min/.test(brut), `(fraîcheur) la cadence déclarée n'est pas rendue à côté du nom : « ${brut} »`);
  exiger(/Il ne devient un retard que pour une source dont la sonde DÉCLARE une cadence continue/.test(brut), "(fraîcheur) l'en-tête ne dit plus ce qu'est un retard");
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
  const libelle = (id) => (liens.find((l) => l.space === id) || {}).label;
  exiger(libelle("search") === "Recherche", `(8) l'espace de l'éditeur de requête ne s'appelle pas « Recherche » (« ${libelle("search")} »)`);
  exiger(libelle("cases") === "Cas", `(8) l'espace du flux alerte -> cas ne s'appelle pas « Cas » (« ${libelle("cases")} »)`);
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
//     nœud texte seul traduit par son parent. Témoin inverse : sous `LANG='fr'`, rien ne bouge.
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
    (n.children || []).forEach((c) => noeudsTexte(c, acc));
    return acc;
  };
  document.createTreeWalker = (root) => { const liste = noeudsTexte(root, []); let i = -1; return { nextNode: () => liste[++i] ?? null }; };
  const attrsDe = (sel) => [...String(sel).matchAll(/\[([a-zA-Z-]+)\]/g)].map((m) => m[1]);
  const qsaOrigine = Element.prototype.querySelectorAll;
  Element.prototype.matches = function (sel) { return attrsDe(sel).some((a) => a in this.attributes); };
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

  // (c) témoin inverse : sous LANG='fr', la même marche ne change rien.
  const wrapFR = new Element("div");
  rendreSysteme(wrapFR, mB, hB);
  walkFR(wrapFR);
  const libellesFR = tuiles(wrapFR).map((t) => t.children.find((c) => c.classList.contains("sys-tile-l")).textContent);
  exiger(libellesFR.includes("CPU cumulé") && !libellesFR.includes("Cumulative CPU"), `(10) LANG='fr' : une tuile Système a été traduite — libellés : ${libellesFR.join(" | ")}`);
  const h2FR = new Element("h2"); h2FR._text = enTete; const boutonFR = new Element("button"); boutonFR.setAttribute("title", infobulle); h2FR.appendChild(boutonFR);
  walkFR(h2FR);
  exiger(h2FR._text === enTete && boutonFR.getAttribute("title") === infobulle, "(10) LANG='fr' : l'en-tête ou son infobulle ont été modifiés");
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
//     par propriété (`.placeholder =`), que le shim ne reflète pas en attribut : sa valeur française est
//     lue ici, sa traduction par attribut est celle que le témoin 10 prouve sur un nœud porteur.
// ---------------------------------------------------------------------------------------------
{
  const SUFFIXE = "?plume-lang=en";
  const urlWeb = (f, suffixe = "") => pathToFileURL(path.join(WEB, f)).href + suffixe;
  const aideFR = await import(urlWeb("help.js"));
  localStorage.setItem("soc_lang", "en");
  const aideEN = await import(urlWeb("help.js", SUFFIXE));
  const { i18nWalk: walkEN } = await import(urlWeb("i18n.js", SUFFIXE));
  localStorage.removeItem("soc_lang");
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
  const gFR = guide(aideFR.renderHelpGuide), gEN = guide(aideEN.renderHelpGuide, walkEN);
  for (const mot of ["Espaces & vues", "GXQL — Référence", "Langage de recherche. Exemples :", "Ouvrir la référence GXQL complète", "Glossaire", "Raccourcis", "Guide intégré de Plume"]) {
    exiger(gFR.texte.includes(mot), `(14) guide sous LANG='fr' : « ${mot} » absent`);
    exiger(!gEN.texte.includes(mot), `(14) guide sous LANG='en' : « ${mot} » est resté en français — la clé manque au lexique`);
  }
  for (const mot of ["Spaces & views", "GXQL — Reference", "Search language. Examples:", "Open the full GXQL reference", "Glossary", "Shortcuts", "In-app guide to Plume"]) {
    exiger(gEN.texte.includes(mot), `(14) guide sous LANG='en' : « ${mot} » absent`);
    exiger(!gFR.texte.includes(mot), `(14) guide sous LANG='fr' : un mot anglais « ${mot} » est rendu`);
  }
  exiger(gFR.sommaire === "Sommaire du guide" && gEN.sommaire === "Guide contents", `(14) nom accessible du sommaire : fr « ${gFR.sommaire} », en « ${gEN.sommaire} »`);
  exiger(gFR.filtre === "Filtrer les termes…", `(14) texte d'attente du filtre du glossaire sous LANG='fr' : « ${gFR.filtre} »`);
  console.log(`[aide] ${ouvreurs.length} ouvreurs de modale : bouton « Fermer » sous fr, « Close » sous en après la marche du lexique ; guide : ${7 * 2} libellés rendus dans la langue de l'instance, nom accessible du sommaire traduit`);
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
// 16. LE PANNEAU D'ACCÈS DONNÉES REND SES CARTES, SA FENÊTRE ET SON PÉRIMÈTRE. Le rendu vit dans
//     `dataaccess.js` (extrait d'`app.js` par déplacement pur) ; il est exercé ici sur le shim, sans réseau :
//     cinq cartes titrées, dont chaque corps dit l'absence de données AVEC la fenêtre d'analyse (la requête
//     ne peut pas partir, le placeholder est remplacé par l'aveu, jamais laissé à « ... ») ; un sélecteur de
//     fenêtre à trois choix avec son nom accessible ; la note de périmètre et ses sept chemins surveillés.
// ---------------------------------------------------------------------------------------------
{
  const { renderDataAccess } = await import(pathToFileURL(path.join(WEB, "dataaccess.js")).href);
  const hote = new Element("div");
  const qsOrigine = document.querySelector;
  document.querySelector = (sel) => (sel === "#da-body" ? hote : qsOrigine(sel));
  try { await renderDataAccess(); await new Promise((r) => setTimeout(r, 0)); } finally { document.querySelector = qsOrigine; }
  const h2De = (el) => { const h = el.children.find((x) => x.tagName === "H2"); return h ? h.textContent : null; };
  const cartes = hote.children.filter((c) => c.tagName === "SECTION" && c.dataset.da);
  exiger(cartes.length === 5, `(16) ${cartes.length} carte(s) d'accès données rendue(s), cinq attendues`);
  const titres = cartes.map(h2De);
  for (const t of ["Qui touche quoi (accès données)", "Intégrité (FIM)", "RBAC Kubernetes (kube-rbac)"]) exiger(titres.includes(t), `(16) carte « ${t} » absente — titres : ${titres.join(" | ")}`);
  const corps = cartes.map((c) => { const b = c.children.find((x) => x.classList.contains("body")); return b ? b.textContent : "(pas de corps)"; });
  exiger(corps.every((t) => t.startsWith("Aucun changement récent (toute la rétention")), `(16) sans réseau, un corps de carte ne dit pas l'absence de données avec sa fenêtre : ${corps.join(" | ")}`);
  const barre = hote.children.find((c) => c.classList.contains("da-winbar"));
  const selecteur = barre && barre.children.find((c) => c.tagName === "SELECT");
  exiger(!!selecteur && selecteur.children.length === 3 && selecteur.getAttribute("aria-label") === "Fenêtre d'analyse (DLP)", `(16) sélecteur de fenêtre : ${selecteur ? selecteur.children.length + " option(s), nom « " + selecteur.getAttribute("aria-label") + " »" : "absent"}`);
  exiger(!!barre && barre.children.some((c) => c.tagName === "SPAN" && c.textContent.startsWith("Fenêtre : toute la rétention")), "(16) le libellé de fenêtre n'annonce pas « toute la rétention »");
  const note = hote.children.find((c) => c.classList.contains("da-note"));
  exiger(!!note && h2De(note) === "Périmètre surveillé (hôte)", `(16) note de périmètre : ${note ? "titre « " + h2De(note) + " »" : "absente"}`);
  const puces = note ? note.children.flatMap((c) => c.children || []).filter((c) => c.classList.contains("plugchip")) : [];
  exiger(puces.length === 7 && puces.some((c) => c.textContent === "/etc/shadow"), `(16) ${puces.length} chemin(s) surveillé(s) rendu(s), sept attendus`);
  console.log(`[accès données] ${cartes.length} cartes, ${corps.length} corps disant l'absence de données avec la fenêtre, sélecteur à ${selecteur ? selecteur.children.length : 0} choix, ${puces.length} chemins surveillés`);
}

if (echecs.length) {
  for (const e of echecs) console.error(`::error::${e}`);
  console.error(`\n${echecs.length} témoin(s) en échec : la surface aplatit un verdict.`);
  process.exit(1);
}
console.log(`OK — ${modules.length} modules web se lient ; le panneau Système rend l'état « NON LISIBLE » avec sa cause sur 5 tuiles, les bilans de boucles et les grandeurs de composant, et la valeur quand le verdict est « lu » (vrai zéro compris) ; un playbook livré et un runbook créé rendent par la même fabrique de ligne, avec le mot de leur état et leur conséquence ; la liste des alertes rend une seule barre d'actions sur tous ses tris, aucune action n'est désactivée au motif d'une facette, et la facette source dit son objet et son étendue ; une technique ATT&CK sans nom se dit, l'éditeur de requête laisse « != » en place sous la frappe, la palette des modèles porte modifier/supprimer/copier, et le badge de troncature nomme le saut de page ; l'inventaire des sources rend attendue / inattendue / marquée avec la raison et offre l'acquittement à l'éditeur ; la fraîcheur rend le statut du démon (une périodique dans sa cadence = frais, jamais « dégradé ») et compte les alertes à part ; une carte d'administration se replie par son bouton sans jamais le griser, un formulaire de création ne rend aucun bouton nu, et la confirmation partagée exige une conséquence nommée, bloque écartée et passe validée ; la sidebar porte deux espaces « Recherche » et « Cas » égaux au modèle de navigation, les alertes sous Cas, l'éditeur seul sous Recherche, chaque section mappée existe, et les deux familles de l'onglet Playbooks sont nommées dans leurs en-têtes et boutons, la durée du ban suivant la valeur servie ; les fabriques de bouton des cas et des producteurs, la barre des alertes et le bloc MFA ne rendent aucun bouton nu ni style en ligne, et chaque bouton d'aide a sa section ; l'aide « Jetons » s'ouvre et dit le secret montré une seule fois, et une clé sans section ouvre un aveu qui la nomme ; le bouton de fermeture des modales d'aide et les titres du guide rendent en anglais par le lexique, jamais par un mot écrit dans le module ; l'amorçage pose l'observateur du lexique sur le corps du document et celui-ci traduit un nœud texte, un élément et un attribut posés après coup ; le panneau d'accès données rend cinq cartes qui disent l'absence de données avec leur fenêtre, son sélecteur et ses sept chemins surveillés.`);
